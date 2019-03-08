extern crate pnet;
extern crate pnet_macros_support;
extern crate lru_time_cache;
use crate::passthrough;

use self::passthrough::backend::{Backend, ServerPool, Node, health_checker};
use self::passthrough::arp::Arp;
use crate::config::{Config, BaseConfig};
use crate::stats::StatsMssg;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket};
use pnet::packet::{tcp, Packet};
use pnet::packet::ipv4::{checksum, Ipv4Packet, MutableIpv4Packet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use pnet::datalink::{self, NetworkInterface};
use pnet::util::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::arp::{MutableArpPacket, ArpOperations, ArpHardwareTypes};
use pnet::datalink::Channel::Ethernet;
use std::sync::{Arc, Mutex, RwLock};
use std::str::FromStr;
use std::sync::mpsc::{Sender, Receiver};
use std::collections::HashMap;
use std::{thread};
use lru_time_cache::LruCache;
use std::time::Duration;
use crossbeam_channel::unbounded;
use std::sync::mpsc::channel;
use self::passthrough::utils::{IPV4_HEADER_LEN, EPHEMERAL_PORT_LOWER, EPHEMERAL_PORT_UPPER, ETHERNET_HEADER_LEN};


#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Client {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct Connection {
    // Client tcp address
    pub client: SocketAddr,

    // backend server the client was scheduled to.  Tracked for future packets
    backend_srv: Node,

    // Unique port assigned to this connection.  Used for mapping responses from
    // backend servers to this client address
    pub ephem_port: u16,
}

// LB represents a single loadbalancer function, listening for an Address
// and scheduling packets on a pool of backend servers
#[derive(Clone)]
pub struct LB {
    // Loadbalancer name.  Maps to frontend name in the config
    pub name: String,

    // Ipv4 Address this loadbalancer listens for
    pub listen_ip: Ipv4Addr,

    // Port this loadbalancer listens for
    pub listen_port: u16,

    // The backend server logic
    pub backend: Arc<Backend>,

    // Connection tracker for bookeeping of client connections.
    // very basic right now, just used for mapping backend servers to clients
    pub conn_tracker: Arc<RwLock<LruCache<Client, Connection>>>,

    // Port mapper for quickly looking up the client address based on
    // the port a backend server sent a response to.
    // Only used in Passthrough mode without DSR (so bidirectional)
    // Since DSR bypasses coming back through the loadbalancer this data structure
    // isn't needed in Passthrough DSR mode
    pub port_mapper: Arc<RwLock<HashMap<u16, Client>>>,

    // Keeping track of the next port to assign for client -> backend server mappings
    pub next_port: Arc<Mutex<u16>>,

    // Number of worker threads to spawn
    pub workers: usize,

    // Flag indicating whether we are operating in Passthrough DSR mode (server response bypasses the loadbalancer)
    // or in plain Passthrough mode (server repsonse returns through the loadbalancer and the loadbalancer
    // sends back to client).
    // False by default (so plain Passthrough/bidirectional)
    pub dsr: bool,

    // How often to update the stats/counters.  5 seconds by default
    pub stats_update_frequency: u64,
}


impl LB {
    pub fn next_avail_port(&mut self) -> u16 {
        let mut port = self.next_port.lock().unwrap();
        if *port < EPHEMERAL_PORT_UPPER {
            *port +=1;
        } else {
            *port = EPHEMERAL_PORT_LOWER;
        }
        *port
    }

    // handle repsonse packets from a backend server passing back through the loadbalancer
    pub fn server_response_handler(&mut self, ip_header: &Ipv4Packet, tcp_header: &mut MutableTcpPacket, client_addr: &SocketAddr, tx: Sender<MutableIpv4Packet>) -> Option<StatsMssg> {
        match client_addr.ip() {
            IpAddr::V4(client_ipv4) => {
                let mut mssg = StatsMssg{frontend: None,
                                    backend: self.backend.name.clone(),
                                    connections: 0,
                                    bytes_tx: 0,
                                    bytes_rx: 0,
                                    servers: None};

                let mut new_ipv4 = MutableIpv4Packet::owned(ip_header.packet().to_vec()).unwrap();
                tcp_header.set_destination(client_addr.port());
                tcp_header.set_source(self.listen_port);
                tcp_header.set_checksum(tcp::ipv4_checksum(&tcp_header.to_immutable(), &self.listen_ip, &client_ipv4));

                new_ipv4.set_total_length(tcp_header.packet().len() as u16 + IPV4_HEADER_LEN as u16);
                new_ipv4.set_version(4);
                new_ipv4.set_ttl(225);
                new_ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                new_ipv4.set_payload(&tcp_header.packet());
                new_ipv4.set_destination(client_ipv4);
                new_ipv4.set_source(self.listen_ip);
                new_ipv4.set_header_length(5);
                new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));
                mssg.bytes_tx = tcp_header.payload().len() as u64;

                match tx.send(new_ipv4) {
                    Ok(n) => {
                        debug!("Client handler sent {:?} packet to outgoing interface handler thread", n);
                        match tcp_header.get_flags() {
                            0b000010010 => mssg.connections = 1, // add a connection to count on SYN,ACK
                            0b000010001 => mssg.connections = -1, // sub a connection to count on FIN,ACK
                            _ => {},
                        }
                        return Some(mssg)
                    }
                    Err(e) => error!("failed to send packet to {:?}: Error: {}", client_addr, e),
                }
            }
            _ => {} // ipv6 not supported (yet)
        }
        return None
    }

    // handle requests packets from a client
    pub fn client_handler(&mut self, ip_header: &Ipv4Packet, tcp_header: &mut MutableTcpPacket, tx: Sender<MutableIpv4Packet>) -> Option<StatsMssg> {
        let client_port = tcp_header.get_source();

        // setup stats update return
        let mut mssg = StatsMssg{frontend: None,
                            backend: self.backend.name.clone(),
                            connections: 0,
                            bytes_tx: 0,
                            bytes_rx: 0,
                            servers: None};

        let mut new_ipv4 = MutableIpv4Packet::owned(ip_header.packet().to_vec()).unwrap();
        new_ipv4.set_total_length(tcp_header.packet().len() as u16 + IPV4_HEADER_LEN as u16);
        new_ipv4.set_version(4);
        new_ipv4.set_ttl(225);
        new_ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        new_ipv4.set_header_length(5);

        // leave original ip source if dsr
        if !self.dsr {
            new_ipv4.set_source(self.listen_ip);
        } else{
            new_ipv4.set_source(ip_header.get_source());
        }

        //check if we are already tracking this connection
        let cli = Client{
            ip: IpAddr::V4(ip_header.get_source()),
            port: client_port,
        };

        if let Some(conn) = self.cli_connection(&cli) {
            debug!("Found existing connection {:?}", conn);
            match conn.backend_srv.host {
                IpAddr::V4(fwd_ipv4) => {
                    if self.backend.get_server_health(conn.backend_srv.clone()) {
                        tcp_header.set_destination(conn.backend_srv.port);

                        // leave original tcp source if dsr
                        if !self.dsr {
                            tcp_header.set_source(conn.ephem_port);
                            tcp_header.set_checksum(tcp::ipv4_checksum(&tcp_header.to_immutable(), &self.listen_ip, &fwd_ipv4));
                        } else {
                            tcp_header.set_checksum(tcp::ipv4_checksum(&tcp_header.to_immutable(), &ip_header.get_source(), &fwd_ipv4));
                        }

                        new_ipv4.set_payload(&tcp_header.packet());
                        new_ipv4.set_destination(fwd_ipv4);
                        new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));

                        match tx.send(new_ipv4) {
                            Ok(n) => {
                                debug!("Client handler sent {:?} packet to outgoing interface handler thread", n);
                            },
                            Err(e) => error!("failed to send packet: {}", e),
                        }
                        mssg.bytes_tx = tcp_header.payload().len() as u64;
                        return Some(mssg)
                    } else {
                        debug!("Backend sever {:?} is no longer healthy.  Rescheduling", conn.backend_srv);
                        // backend server is unhealthy, remove connection from map
                        // leave in port_mapper in case there are still packets from server in flight
                        self.conn_tracker.write().unwrap().remove(&cli);
                    }
                }
                _ => { return None }
            }
        }

        // Either not tracking connection yet or backend server not healthy
        // if backend server previously scheduled is not healthy this is just a best effort.  if RST is neccessary let new backend send it
        if let Some(node) = self.backend.get_server(IpAddr::V4(self.listen_ip), self.listen_port, IpAddr::V4(ip_header.get_source()), tcp_header.get_source()) {
            match node.host {
                IpAddr::V4(fwd_ipv4) => {
                    tcp_header.set_destination(node.port);

                    // leave original tcp source if dsr
                    let mut ephem_port = 0 as u16;
                    if !self.dsr {
                        // set ephemeral port for tracking connections and in case of mutiple clients using same port
                        ephem_port = self.clone().next_avail_port();
                        debug!("Using Ephemeral port {} for client connection {:?}", ephem_port, SocketAddr::new(IpAddr::V4(ip_header.get_source()), client_port));
                        tcp_header.set_source(ephem_port);
                        tcp_header.set_checksum(tcp::ipv4_checksum(&tcp_header.to_immutable(), &self.listen_ip, &fwd_ipv4));
                    } else {
                        tcp_header.set_checksum(tcp::ipv4_checksum(&tcp_header.to_immutable(), &ip_header.get_source(), &fwd_ipv4));
                    }

                    new_ipv4.set_payload(&tcp_header.packet());
                    new_ipv4.set_destination(fwd_ipv4);
                    new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));

                    match tx.send(new_ipv4) {
                        Ok(n) => {
                            debug!("Client handler sent {:?} packet to outgoing interface handler thread", n);
                        }
                        Err(e) => error!("failed to send packet: {}", e),
                    }

                    mssg.bytes_tx = tcp_header.payload().len() as u64;

                    // not already tracking the connection so insert into our maps
                    let conn = Connection {
                        client: SocketAddr::new(IpAddr::V4(ip_header.get_source()), client_port),
                        backend_srv: node,
                        ephem_port: ephem_port,
                    };
                    {
                        self.conn_tracker.write().unwrap().insert(cli, conn);
                    }
                    {
                        self.port_mapper.write().unwrap().insert(ephem_port, Client{ip: IpAddr::V4(ip_header.get_source()), port: client_port});
                    }
                    return Some(mssg)
                }
                _ => { return None }
            }
        } else {
            error!("Unable to find backend");
            // Send RST to client
            tcp_header.set_source(self.listen_port);
            tcp_header.set_destination(tcp_header.get_source());
            if tcp_header.get_flags() == tcp::TcpFlags::SYN {
                // reply ACK, RST
                tcp_header.set_flags(0b000010100);
            } else {
                tcp_header.set_flags(tcp::TcpFlags::RST);
            }
            tcp_header.set_acknowledgement(tcp_header.get_sequence().clone() + 1);
            tcp_header.set_sequence(0);
            tcp_header.set_window(0);
            tcp_header.set_checksum(tcp::ipv4_checksum(&tcp_header.to_immutable(), &self.listen_ip, &ip_header.get_source()));

            new_ipv4.set_payload(&tcp_header.packet());
            new_ipv4.set_total_length(tcp_header.packet().len() as u16 + IPV4_HEADER_LEN as u16);
            new_ipv4.set_destination(ip_header.get_source());
            new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));

            match tx.send(new_ipv4) {
                Ok(n) => debug!("Client handler sent {:?} packet to outgoing interface handler thread", n),
                Err(e) => error!("failed to send packet: {}", e),
            }
            let mut connections = 0;
            if !self.dsr {
                connections = -1;
            }
            mssg.connections = connections;
            return Some(mssg)
        }
    }

    fn cli_connection(&mut self, cli: &Client) -> Option<Connection>{
        // by using a peek instead of get we can get away with a read lock
        if let Some(conn) = self.conn_tracker.read().unwrap().peek(&cli) {
            return Some(conn.clone());
        }
        None
    }
}
