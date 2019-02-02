extern crate pnet;
extern crate pnet_macros_support;
extern crate threadpool;
extern crate lru_time_cache;

use self::backend::{Backend, ServerPool, Node, health_checker};
use crate::config::{Config, BaseConfig};
use crate::stats::StatsMssg;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel};
use pnet::transport::{TransportSender};
use pnet::transport::TransportChannelType::{Layer3};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
use pnet::packet::{tcp};
use pnet::packet::ipv4::{checksum, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};
use std::net::{IpAddr, Ipv4Addr};
use pnet::datalink::{self, NetworkInterface, MacAddr};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{MutableEthernetPacket};

use std::sync::{Arc, Mutex};
use std::net::{SocketAddr};
use std::str::FromStr;
use std::sync::mpsc::{Sender, Receiver};
use std::collections::HashMap;
use std::{thread};
use lru_time_cache::LruCache;
use tokio::prelude::*;
use tokio::timer::Interval;
use std::time::{Duration, Instant};
use futures::future::lazy;
use crossbeam_channel::unbounded;
use std::sync::mpsc::channel;

const IPV4_HEADER_LEN: usize = 20;
const ETHERNET_HEADER_LEN: usize = 14;
const EPHEMERAL_PORT_LOWER: u16 = 32768;
const EPHEMERAL_PORT_UPPER: u16 = 61000;

mod backend;

#[derive(Clone)]
pub struct Server {
    pub lbs: Vec<LB>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
struct Client {
    ip: IpAddr,
    port: u16,
}

#[derive(Clone, Debug)]
struct Connection {
    // Client tcp address
    client: SocketAddr,

    // backend server the client was scheduled to.  Tracked for future packets
    backend_srv: Node,

    // Unique port assigned to this connection.  Used for mapping responses from
    // backend servers to this client address
    ephem_port: u16,
}

// LB represents a single loadbalancer function, listening for an Address
// and scheduling packets on a pool of backend servers
#[derive(Clone)]
pub struct LB {
    // Loadbalancer name.  Maps to frontend name in the config
    name: String,

    // Ipv4 Address this loadbalancer listens for
    listen_ip: Ipv4Addr,

    // Port this loadbalancer listens for
    listen_port: u16,

    // The backend server logic
    backend: Arc<Backend>,

    // Connection tracker for bookeeping of client connections.
    // very basic right now, just used for mapping backend servers to clients
    conn_tracker: Arc<Mutex<LruCache<Client, Connection>>>,

    // Port mapper for quickly looking up the client address based on
    // the port a backend server sent a response to.
    // Only used in Passthrough mode without DSR (so bidirectional)
    // Since DSR bypasses coming back through the loadbalancer this data structure
    // isn't needed in Passthrough DSR mode
    port_mapper: Arc<Mutex<HashMap<u16, Client>>>,

    // Keeping track of the next port to assign for client -> backend server mappings
    next_port: Arc<Mutex<u16>>,

    // Number of worker threads to spawn
    workers: usize,

    // Flag indicating whether we are operating in Passthrough DSR mode (server response bypasses the loadbalancer)
    // or in plain Passthrough mode (server repsonse returns through the loadbalancer and the loadbalancer
    // sends back to client).
    // False by default (so plain Passthrough/bidirectional)
    dsr: bool,

    // How often to update the stats/counters.  5 seconds by default
    stats_update_frequency: u64,
}

// Server is the overarching type, comprised of at least one loadbalancer
impl Server {
    pub fn new(config: Config) -> Server {
        let mut new_server = Server {lbs: Vec::new()};
        for (name,front) in config.base.frontends.iter() {
            let mut backend_servers = HashMap::new();

            // Set defaults
            let mut health_check_interval = 5;
            let mut connection_tracker_capacity = 1000 as usize;
            let mut workers = 4 as usize;
            let mut dsr = false;
            let mut stats_update_frequency = 5;

            match config.base.passthrough {
                Some(setting) => {
                    connection_tracker_capacity = setting.connection_tracker_capacity;
                    if let Some(num) = setting.workers {
                        workers = num;
                    }
                    if let Some(flag) = setting.dsr {
                        dsr = flag;
                    }
                    if let Some(freq) = setting.stats_update_frequency {
                        stats_update_frequency = freq;
                    }
                },
                None => {},
            }

            match config.base.backends.get(&front.backend) {
                Some(back) => {
                    for (_,addr) in &back.servers {
                        let listen_addr: SocketAddr = FromStr::from_str(&addr.addr)
                                          .ok()
                                          .expect("Failed to parse listen host:port string");
                        backend_servers.insert(listen_addr, addr.weight);
                    }
                    if back.health_check_interval > 0 {
                        health_check_interval = back.health_check_interval;
                    }
                }
                None => {
                    error!("Error finding backend server pool in config: {} not found on backend config", front.backend);
                    continue
                },
            };

            if backend_servers.len() > 0 {
                let listen_addr: SocketAddr = FromStr::from_str(&front.listen_addr)
                                  .ok()
                                  .expect("Failed to parse listen host:port string");

                let backend = Arc::new(Backend::new(front.backend.clone(), backend_servers, health_check_interval));
                match listen_addr.ip() {
                    IpAddr::V4(ip4) => {
                        let new_lb = LB {
                            name: name.clone(),
                            listen_ip: ip4,
                            listen_port: listen_addr.port(),
                            backend: backend.clone(),
                            conn_tracker: Arc::new(Mutex::new(LruCache::<Client, Connection>::with_capacity(connection_tracker_capacity))),
                            port_mapper: Arc::new(Mutex::new(HashMap::new())),
                            next_port: Arc::new(Mutex::new(EPHEMERAL_PORT_LOWER)),
                            workers: workers,
                            dsr: dsr,
                            stats_update_frequency: stats_update_frequency,
                        };
                        new_server.lbs.push(new_lb);
                    }
                    _ => error!("Unable to configure load balancer server {:?}.  Only Ipv4 is supported", front),
                }
            } else {
                error!("Unable to configure load balancer server {:?}", front);
            }
        }
        let rx = config.subscribe();
        new_server.config_sync(rx);
        new_server
    }

    // wait on config changes to update backend server pool
    fn config_sync(&mut self, rx: Receiver<BaseConfig>) {
        let mut lbs = self.lbs.clone();
        thread::spawn( move || {
            loop {
                match rx.recv() {
                    Ok(new_config) => {
                        debug!("Config file watch event. New config: {:?}", new_config);
                        for (backend_name, backend) in new_config.backends {
                            let mut backend_servers = HashMap::new();
                            for (_, server) in backend.servers {
                                let listen_addr: SocketAddr = FromStr::from_str(&server.addr)
                                                  .ok()
                                                  .expect("Failed to parse listen host:port string");
                                backend_servers.insert(listen_addr, server.weight);
                            }
                            for lb in lbs.iter_mut() {
                                if lb.backend.name == backend_name {
                                    info!("Updating backend {} with {:?}", backend_name, backend_servers.clone());
                                    let srv_pool = ServerPool::new_servers(backend_servers.clone());
                                    *lb.backend.servers_map.write().unwrap() = srv_pool.servers_map;
                                    *lb.backend.ring.lock().unwrap() = srv_pool.ring;
                                }
                            }
                        }
                    }
                    Err(e) => error!("watch error: {:?}", e),
                }
            }
        });
    }

    pub fn run(self, sender: Sender<StatsMssg>) {
        let mut threads = Vec::new();
        for lb in self.lbs.iter() {
            let srv_thread = lb.clone();
            let thread_sender = sender.clone();
            let t = thread::spawn(move ||{
                run_server(srv_thread, thread_sender);
            });
            threads.push(t);
        }
        for t in threads {
            t.join().expect("thread failed");
        }
    }
}

impl LB {
    fn next_avail_port(&mut self) -> u16 {
        let mut port = self.next_port.lock().unwrap();
        if *port < EPHEMERAL_PORT_UPPER {
            *port +=1;
        } else {
            *port = EPHEMERAL_PORT_LOWER;
        }
        *port
    }

    // handle repsonse packets from a backend server passing back through the loadbalancer
    fn server_response_handler(&mut self, ip_header: &Ipv4Packet, client_addr: &SocketAddr, tx: Sender<MutableIpv4Packet>) -> Option<StatsMssg> {
        let tcp_header = match TcpPacket::new(ip_header.payload()) {
            Some(tcp_header) => tcp_header,
            None => {
                error!("Unable to decapsulate tcp header");
                return None
            }
        };

        match client_addr.ip() {
            IpAddr::V4(client_ipv4) => {
                let mut mssg = StatsMssg{frontend: None,
                                    backend: self.backend.name.clone(),
                                    connections: 0,
                                    bytes_tx: 0,
                                    bytes_rx: 0,
                                    servers: None};

                let mut vec: Vec<u8> = vec![0; tcp_header.packet().len()];
                let mut new_tcp = MutableTcpPacket::new(&mut vec[..]).unwrap();
                new_tcp.clone_from(&tcp_header);

                let ipbuf: Vec<u8> = vec!(0; new_tcp.packet().len() + IPV4_HEADER_LEN);
                let mut new_ipv4 = MutableIpv4Packet::owned(ipbuf).unwrap();
                new_ipv4.clone_from(ip_header);
                new_tcp.set_destination(client_addr.port());
                new_tcp.set_source(self.listen_port);
                new_tcp.set_checksum(tcp::ipv4_checksum(&new_tcp.to_immutable(), &self.listen_ip, &client_ipv4));

                new_ipv4.set_total_length(new_tcp.packet().len() as u16 + IPV4_HEADER_LEN as u16);
                new_ipv4.set_version(4);
                new_ipv4.set_ttl(225);
                new_ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                new_ipv4.set_payload(&new_tcp.packet());
                new_ipv4.set_destination(client_ipv4);
                new_ipv4.set_source(self.listen_ip);
                new_ipv4.set_header_length(5);
                new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));
                mssg.bytes_tx = new_tcp.payload().len() as u64;

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
    fn client_handler(&mut self, ip_header: &Ipv4Packet, tx: Sender<MutableIpv4Packet>) -> Option<StatsMssg> {
        let tcp_header = match TcpPacket::new(ip_header.payload()) {
            Some(tcp_header) => tcp_header,
            None => {
                error!("Unable to decapsulate tcp header");
                return None
            }
        };

        // setup stats update return
        let mut mssg = StatsMssg{frontend: None,
                            backend: self.backend.name.clone(),
                            connections: 0,
                            bytes_tx: 0,
                            bytes_rx: 0,
                            servers: None};

        // setup forwarding packet
        let mut vec: Vec<u8> = vec![0; tcp_header.packet().len()];
        let mut new_tcp = MutableTcpPacket::new(&mut vec[..]).unwrap();
        new_tcp.clone_from(&tcp_header);

        let ipbuf: Vec<u8> = vec!(0; new_tcp.packet().len() + IPV4_HEADER_LEN);
        let mut new_ipv4 = MutableIpv4Packet::owned(ipbuf).unwrap();

        new_ipv4.clone_from(ip_header);
        new_ipv4.set_total_length(tcp_header.packet().len() as u16 + IPV4_HEADER_LEN as u16);
        new_ipv4.set_version(4);
        new_ipv4.set_ttl(225);
        new_ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        new_ipv4.set_header_length(5);

        // leave original ip source if dsr
        if !self.dsr {
            new_ipv4.set_source(self.listen_ip);
        }

        //check if we are already tracking this connection
        let cli = Client{
            ip: IpAddr::V4(ip_header.get_source()),
            port: tcp_header.get_source(),
        };

        // flag for removing client connection from connection tracker
        let mut cli_unhealthy = false;

        if let Some(conn) = self.cli_connection(&cli) {
            debug!("Found existing connection {:?}", conn);
            match conn.backend_srv.host {
                IpAddr::V4(node_ipv4) => {
                    let fwd_ipv4 = node_ipv4.clone();
                    if self.backend.get_server_health(conn.backend_srv.clone()) {
                        new_tcp.set_destination(conn.backend_srv.port);

                        // leave original tcp source if dsr
                        if !self.dsr {
                            new_tcp.set_source(conn.ephem_port);
                            new_tcp.set_checksum(tcp::ipv4_checksum(&new_tcp.to_immutable(), &self.listen_ip, &fwd_ipv4));
                        } else {
                            new_tcp.set_checksum(tcp::ipv4_checksum(&new_tcp.to_immutable(), &ip_header.get_source(), &fwd_ipv4));
                        }

                        new_ipv4.set_payload(&new_tcp.packet());
                        new_ipv4.set_destination(fwd_ipv4);
                        new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));
                        mssg.bytes_tx = new_tcp.payload().len() as u64;

                        match tx.send(new_ipv4) {
                            Ok(n) => {
                                debug!("Client handler sent {:?} packet to outgoing interface handler thread", n);
                            },
                            Err(e) => error!("failed to send packet: {}", e),
                        }
                        return Some(mssg)
                    } else {
                        debug!("Backend sever {:?} is no longer healthy.  Rescheduling", conn.backend_srv);
                        // backend server is unhealthy, remove connection from map
                        // leave in port_mapper in case there are still packets from server in flight
                        cli_unhealthy = true;
                    }
                }
                _ => { return None }
            }
        }

        // Backend server was flagged as unhealthy.  remove from connection tracker
        if cli_unhealthy {
            self.conn_tracker.lock().unwrap().remove(&cli);
        }

        // Either not tracking connection yet or backend server not healthy
        // if backend server previously scheduled is not healthy this is just a best effort.  if RST is neccessary let new backend send it
        if let Some(node) = self.backend.get_server(IpAddr::V4(self.listen_ip), self.listen_port, IpAddr::V4(ip_header.get_source()), tcp_header.get_source()) {
            match node.host {
                IpAddr::V4(node_ipv4) => {
                    let fwd_ipv4 = node_ipv4.clone();
                    new_tcp.set_destination(node.port);

                    // leave original tcp source if dsr
                    let mut ephem_port = 0 as u16;
                    if !self.dsr {
                        // set ephemeral port for tracking connections and in case of mutiple clients using same port
                        ephem_port = self.clone().next_avail_port();
                        debug!("Using Ephemeral port {} for client connection {:?}", ephem_port, SocketAddr::new(IpAddr::V4(ip_header.get_source()), tcp_header.get_source()));
                        {
                            self.port_mapper.lock().unwrap().insert(ephem_port, Client{ip: IpAddr::V4(ip_header.get_source()), port: tcp_header.get_source()});
                        }
                        new_tcp.set_source(ephem_port);
                        new_tcp.set_checksum(tcp::ipv4_checksum(&new_tcp.to_immutable(), &self.listen_ip, &fwd_ipv4));
                    } else {
                        new_tcp.set_checksum(tcp::ipv4_checksum(&new_tcp.to_immutable(), &ip_header.get_source(), &fwd_ipv4));
                    }

                    new_ipv4.set_payload(&new_tcp.packet());
                    new_ipv4.set_destination(fwd_ipv4);
                    new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));
                    mssg.bytes_tx = new_tcp.payload().len() as u64;

                    match tx.send(new_ipv4) {
                        Ok(n) => {
                            debug!("Client handler sent {:?} packet to outgoing interface handler thread", n);
                        }
                        Err(e) => error!("failed to send packet: {}", e),
                    }

                    // not already tracking the connection so insert into our maps
                    let conn = Connection {
                        client: SocketAddr::new(IpAddr::V4(ip_header.get_source()), tcp_header.get_source()),
                        backend_srv: node,
                        ephem_port: ephem_port,
                    };
                    self.conn_tracker.lock().unwrap().insert(cli, conn);
                    return Some(mssg)
                }
                _ => { return None }
            }
        } else {
            error!("Unable to find backend");
            // Send RST to client
            new_tcp.set_source(self.listen_port);
            new_tcp.set_destination(tcp_header.get_source());
            if tcp_header.get_flags() == tcp::TcpFlags::SYN {
                // reply ACK, RST
                new_tcp.set_flags(0b000010100);
            } else {
                new_tcp.set_flags(tcp::TcpFlags::RST);
            }
            new_tcp.set_acknowledgement(tcp_header.get_sequence().clone() + 1);
            new_tcp.set_sequence(0);
            new_tcp.set_window(0);
            new_tcp.set_checksum(tcp::ipv4_checksum(&new_tcp.to_immutable(), &self.listen_ip, &ip_header.get_source()));

            new_ipv4.set_payload(&new_tcp.packet());
            new_ipv4.set_total_length(new_tcp.packet().len() as u16 + IPV4_HEADER_LEN as u16);
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
        if let Some(conn) = self.conn_tracker.lock().unwrap().get(&cli) {
            return Some(conn.clone());
        }
        None
    }
}

fn find_interface(addr: Ipv4Addr) -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    for interface in interfaces {
        for ip in interface.clone().ips {
            if ip.ip() == addr {
                return Some(interface)
            }
        }
    }
    return None
}

// worker thread
fn process_packets(lb: &mut LB, rx: crossbeam_channel::Receiver<EthernetPacket>, tx: Sender<MutableIpv4Packet>, sender: Sender<StatsMssg>) {
    let mut stats = StatsMssg{frontend: Some(lb.name.clone()),
                        backend: lb.backend.name.clone(),
                        connections: 0,
                        bytes_tx: 0,
                        bytes_rx: 0,
                        servers: None};

    // Spawn timer for sending stats updates
    let (stats_tx, stats_rx) = channel();
    let freq = lb.stats_update_frequency;
    thread::spawn(move || {
        loop {
            stats_tx.send("tick").unwrap();
            thread::sleep(Duration::from_secs(freq));
        }
    });

    let loop_tx = tx.clone();
    loop {
        match rx.recv() {
            Ok(ethernet) => {
                match Ipv4Packet::new(ethernet.payload()) {
                    Some(ip_header) => {
                        let ip_addr = ip_header.get_destination();
                        if ip_addr == lb.listen_ip {
                            match TcpPacket::new(ip_header.payload()) {
                                Some(tcp_header) => {
                                    if tcp_header.get_destination() == lb.listen_port {
                                        if let Some(stats_update) = lb.client_handler(&ip_header, loop_tx.clone()) {
                                            stats.connections += &stats_update.connections;
                                            stats.bytes_rx += &stats_update.bytes_rx;
                                            stats.bytes_tx += &stats_update.bytes_tx;
                                        };
                                    } else if !lb.dsr {
                                        // only handling server repsonses if not using dsr
                                        if let Some(client_addr) = lb.port_mapper.lock().unwrap().get_mut(&tcp_header.get_destination()) {
                                            // if true the client socketaddr is in portmapper and the connection/response from backend server is relevant
                                            if let Some(stats_update) = lb.clone().server_response_handler(&ip_header, &SocketAddr::new( client_addr.ip, client_addr.port), loop_tx.clone()) {
                                                stats.connections += &stats_update.connections;
                                                stats.bytes_rx += &stats_update.bytes_rx;
                                                stats.bytes_tx += &stats_update.bytes_tx;
                                            };
                                        }
                                    }
                                    match stats_rx.try_recv() {
                                        Ok(_) => {
                                            // send the counters we've gathered in this time period
                                            debug!("Timer fired, sending stats counters");
                                            match sender.send(stats.clone()) {
                                                Ok(_) => {},
                                                Err(e) => error!("Error sending stats message on channel: {}", e)
                                            }
                                            // zero out counters for next time period
                                            stats.connections = 0;
                                            stats.bytes_rx = 0;
                                            stats.bytes_tx = 0;
                                        }
                                        Err(_) => {},
                                    }
                                },
                                None => {},
                            }
                        }
                    },
                    None => {},
                }
            }
            Err(e) => error!("Error receiving packet on channel {}", e),
        }
    }
}

pub fn run_server(lb: LB, sender: Sender<StatsMssg>) {
    debug!("Listening for: {:?}, {:?}", lb.listen_ip, lb.listen_port);
    debug!("Load Balancing to: {:?}", lb.backend.name);

    let backend = lb.backend.clone();
    let health_sender = sender.clone();
    thread::spawn( move || {
        sched_health_checks(backend, health_sender);
    });
    let interface = match find_interface(lb.listen_ip) {
        Some(interface) => {
            if interface.is_loopback() {
                error!("Supplied address is on a loopback interface");
                return
            }
            println!("Listening on interface {}", interface);
            interface
        }
        None => {
            error!("Unable to find network interface with IP {:?}.  Skipping {}", lb.listen_ip, lb.name);
            return
        }
    };

    // Create a new channel, dealing with layer 2 packets
    let (mut iface_tx, mut iface_rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    // multi producer / multi receiver channel for main thread to distribute
    // incoming ethernet packets to multiple workers
    let (incoming_tx, incoming_rx) = unbounded();

    let (outgoing_tx, outgoing_rx) = channel();
    // multi producer / single receiver channel for worker threads to
    // send outgoing ethernet packets

    for _ in 0..lb.workers {
        let mut thread_lb = lb.clone();
        let thread_rx = incoming_rx.clone();
        let thread_tx = outgoing_tx.clone();
        let thread_sender = sender.clone();
        thread::spawn(move || {
            process_packets(&mut thread_lb, thread_rx, thread_tx, thread_sender)
        });
    }

    // tx thread for sending processed packets back out
    thread::spawn(move || {
        let tx_protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (mut tx, _) = match transport_channel(4096, tx_protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => {
                error!("Error setting up TCP transport channel {}", e);
                return
            },
        };
        loop {
            match outgoing_rx.recv() {
                Ok(ip_header) => {
                    let dst = IpAddr::V4(ip_header.get_destination());
                    match tx.send_to(ip_header, dst) {
                       Ok(n) => {
                           debug!("Sent {} bytes to Server", n);
                       },
                       Err(e) => error!("failed to send packet: {}", e),
                    }
                }
                Err(e) => error!("Error processing outgoing packet {:?}", e),
            }
        }
    });

    loop {
        match iface_rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::owned(packet.to_owned()).unwrap();
                match ethernet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        match incoming_tx.send(ethernet) {
                            Ok(_) => {},
                            Err(e) => error!("Error sending ethernet packet to worker on channel {}", e)
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                error!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn sched_health_checks(backend: Arc<Backend>, sender: Sender<StatsMssg>) {
    tokio::run(lazy( move || {
        // schedule health checker
        let time = backend.health_check_interval;
        let timer_sender = sender.clone();
        let task = Interval::new(Instant::now(), Duration::from_secs(time))
            .for_each(move |instant| {
                health_checker(backend.clone(), &timer_sender);
                debug!("Running backend health checker{:?}", instant);
                Ok(())
            })
            .map_err(|e| panic!("interval errored; err={:?}", e));
        tokio::spawn(task);
        Ok(())
    }));
}


#[cfg(test)]
mod tests {
    extern crate hyper;
    use std::sync::mpsc::channel;
    use std::thread;
    use crate::config::{Config};
    use crate::passthrough;
    use crate::stats;
    use hyper::{Body, Request, Response, Server};
    use hyper::service::service_fn_ok;
    use hyper::rt::{self, Future};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::{time};

    fn update_config(filename: &str, word_from: String, word_to: String) {
        let mut src = File::open(&filename).unwrap();
        let mut data = String::new();
        src.read_to_string(&mut data).unwrap();
        drop(src);  // Close the file early

        // Run the replace operation in memory
        let new_data = data.replace(&*word_from, &*word_to);

        // Recreate the file and dump the processed contents to it
        let mut dst = File::create(&filename).unwrap();
        dst.write(new_data.as_bytes()).unwrap();
    }

    fn find_test_ip() -> Option<String> {
        for iface in pnet::datalink::interfaces() {
            if !iface.is_loopback() {
                for ipnet in iface.ips {
                    if ipnet.is_ipv4() {
                        return Some(ipnet.ip().to_string());
                    }
                }
            }
        }
        return None;
    }

    #[test]
    fn test_passthrough() {
        // setup iptables for passthrough mode (iptables -t raw -A PREROUTING -p tcp --dport 3000 -j DROP)

        let test_ip = find_test_ip().unwrap();
        update_config("testdata/passthrough_test.toml", "127.0.0.1:3080".to_string(), format!("{}{}", test_ip.clone(), ":3080"));
        update_config("testdata/passthrough_test.toml", "127.0.0.1:3081".to_string(), format!("{}{}", test_ip.clone(), ":3081"));

        let thread_ip = test_ip.clone();
        thread::spawn( move ||{
            let addr = format!("{}{}", "127.0.0.1", ":3080").parse().unwrap();
            let server = Server::bind(&addr)
            .serve(|| {
                service_fn_ok(move |_: Request<Body>| {
                    Response::new(Body::from("Success DummyA Server"))
                })
            })
            .map_err(|e| eprintln!("server error: {}", e));
            rt::run(server);
        });

        let mut conf = Config::new("testdata/passthrough_test.toml").unwrap();
        conf.base.frontends.get_mut("tcp_3000").unwrap().listen_addr = format!("{}{}", "127.0.0.1", ":3000");

        let lb = passthrough::Server::new(conf);
        //TODO: verify messages sent over channel to stats endpoint from proxy
        let (tx, _) = channel();

        thread::spawn( ||{
            lb.run(tx);
        });

        let two_secs = time::Duration::from_secs(2);
        thread::sleep(two_secs);
        let curl_req = format!("{}{}{}", "http://", "127.0.0.1", ":3000");
        // validate scheduling
        for _ in 0..10 {
            let mut resp = reqwest::get(curl_req.as_str()).unwrap();
            assert_eq!(resp.status(), 200);
            assert!(resp.text().unwrap().contains("DummyA"));
        }

        // update config to take DummyA out of service
        update_config("testdata/passthrough_test.toml", format!("{}{}", "127.0.0.1", ":3080"), format!("{}{}", "127.0.0.1", ":3083"));
        thread::sleep(two_secs);

        // start dummyB server
        //let thread_ip = test_ip.clone();
        thread::spawn(move ||{
            let addr = format!("{}{}", "127.0.0.1", ":3081").parse().unwrap();
            let server = Server::bind(&addr)
            .serve(|| {
                service_fn_ok(move |_: Request<Body>| {
                    Response::new(Body::from("Success DummyB Server"))
                })
            })
            .map_err(|e| eprintln!("server error: {}", e));
            rt::run(server);
        });

        let two_secs = time::Duration::from_secs(2);
        thread::sleep(two_secs);

        // validate only DummyB is serving requests now that DummyA has been taken out of service
        for _ in 0..10 {
            let mut resp = reqwest::get(curl_req.as_str()).unwrap();
            assert_eq!(resp.status(), 200);
            assert!(resp.text().unwrap().contains("DummyB"));
        }

        // reset fixture

        // update_config("testdata/passthrough_test.toml", format!("{}{}", test_ip.clone(), ":3083"), "127.0.0.1:3080".to_string());
        // update_config("testdata/passthrough_test.toml", format!("{}{}", test_ip.clone(), ":3081"), "127.0.0.1:3081".to_string());
        // Flush iptables
    }
}
