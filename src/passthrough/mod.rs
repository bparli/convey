extern crate pnet;
extern crate pnet_macros_support;
extern crate lru_time_cache;

use self::backend::{Backend, ServerPool, Node, health_checker};
use crate::config::{Config, BaseConfig};
use crate::stats::StatsMssg;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel};
use pnet::transport::TransportChannelType::{Layer3};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
use pnet::packet::{tcp};
use pnet::packet::ipv4::{checksum, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::datalink::Channel::Ethernet;
use std::sync::{Arc, Mutex};
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
const EPHEMERAL_PORT_LOWER: u16 = 32768;
const EPHEMERAL_PORT_UPPER: u16 = 61000;

mod backend;
mod utils;

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
    pub fn new(config: Config, dsr: bool) -> Server {
        let mut new_server = Server {lbs: Vec::new()};
        for (name,front) in config.base.frontends.iter() {
            let mut backend_servers = HashMap::new();

            // Set defaults
            let mut health_check_interval = 5;
            let mut connection_tracker_capacity = 1000 as usize;
            let mut workers = 4 as usize;
            let mut stats_update_frequency = 5;

            match config.base.passthrough {
                Some(setting) => {
                    connection_tracker_capacity = setting.connection_tracker_capacity;
                    if let Some(num) = setting.workers {
                        workers = num;
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
                        info!("Config file watch event. New config: {:?}", new_config);
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
                                    debug!("Updating backend {} with {:?}", backend_name, backend_servers.clone());
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
        let mut tcp_header = match MutableTcpPacket::owned(ip_header.payload().to_owned()) {
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

                let ipbuf: Vec<u8> = vec!(0; tcp_header.packet().len() + IPV4_HEADER_LEN);
                let mut new_ipv4 = MutableIpv4Packet::owned(ipbuf).unwrap();
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
    fn client_handler(&mut self, ip_header: &Ipv4Packet, tx: Sender<MutableIpv4Packet>) -> Option<StatsMssg> {
        let mut tcp_header = match MutableTcpPacket::owned(ip_header.payload().to_owned()) {
            Some(tcp_header) => tcp_header,
            None => {
                error!("Unable to decapsulate tcp header");
                return None
            }
        };

        let client_port = tcp_header.get_source();

        // setup stats update return
        let mut mssg = StatsMssg{frontend: None,
                            backend: self.backend.name.clone(),
                            connections: 0,
                            bytes_tx: 0,
                            bytes_rx: 0,
                            servers: None};

        let ipbuf: Vec<u8> = vec!(0; tcp_header.packet().len() + IPV4_HEADER_LEN);
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
            port: client_port,
        };

        // flag for removing client connection from connection tracker
        let mut cli_unhealthy = false;

        if let Some(conn) = self.cli_connection(&cli) {
            debug!("Found existing connection {:?}", conn);
            match conn.backend_srv.host {
                IpAddr::V4(node_ipv4) => {
                    if self.backend.get_server_health(conn.backend_srv.clone()) {
                        let fwd_ipv4 = node_ipv4.clone();
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
                        mssg.bytes_tx = tcp_header.payload().len() as u64;

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
                    tcp_header.set_destination(node.port);

                    // leave original tcp source if dsr
                    let mut ephem_port = 0 as u16;
                    if !self.dsr {
                        // set ephemeral port for tracking connections and in case of mutiple clients using same port
                        ephem_port = self.clone().next_avail_port();
                        debug!("Using Ephemeral port {} for client connection {:?}", ephem_port, SocketAddr::new(IpAddr::V4(ip_header.get_source()), client_port));
                        {
                            self.port_mapper.lock().unwrap().insert(ephem_port, Client{ip: IpAddr::V4(ip_header.get_source()), port: client_port});
                        }
                        tcp_header.set_source(ephem_port);
                        tcp_header.set_checksum(tcp::ipv4_checksum(&tcp_header.to_immutable(), &self.listen_ip, &fwd_ipv4));
                    } else {
                        tcp_header.set_checksum(tcp::ipv4_checksum(&tcp_header.to_immutable(), &ip_header.get_source(), &fwd_ipv4));
                    }

                    new_ipv4.set_payload(&tcp_header.packet());
                    new_ipv4.set_destination(fwd_ipv4);
                    new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));
                    mssg.bytes_tx = tcp_header.payload().len() as u64;

                    match tx.send(new_ipv4) {
                        Ok(n) => {
                            debug!("Client handler sent {:?} packet to outgoing interface handler thread", n);
                        }
                        Err(e) => error!("failed to send packet: {}", e),
                    }

                    // not already tracking the connection so insert into our maps
                    let conn = Connection {
                        client: SocketAddr::new(IpAddr::V4(ip_header.get_source()), client_port),
                        backend_srv: node,
                        ephem_port: ephem_port,
                    };
                    {
                        self.conn_tracker.lock().unwrap().insert(cli, conn);
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
                    Some(mut ip_header) => {
                        let ip_addr = ip_header.get_destination();
                        if ip_addr == lb.listen_ip {
                            match TcpPacket::new(ip_header.payload()) {
                                Some(tcp_header) => {
                                    if tcp_header.get_destination() == lb.listen_port {
                                        if let Some(stats_update) = lb.client_handler(&mut ip_header, loop_tx.clone()) {
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
    let (_, mut iface_rx) = match datalink::channel(&interface, Default::default()) {
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

    // spawn the packet processing workers
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
    use hyper::{Body, Request, Response, Server};
    use hyper::service::service_fn_ok;
    use hyper::rt::{self, Future};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::{time};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use self::passthrough::utils::{build_dummy_eth, build_dummy_ip};
    use self::passthrough::{EPHEMERAL_PORT_LOWER, EPHEMERAL_PORT_UPPER, Node, process_packets};
    use pnet::packet::tcp::{TcpPacket};
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::Packet;
    use crossbeam_channel::unbounded;

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

    #[test]
    fn test_new_passthrough() {
        // thread::spawn( move ||{
        //     let addr = format!("{}{}", "127.0.0.1", ":3080").parse().unwrap();
        //     let server = Server::bind(&addr)
        //     .serve(|| {
        //         service_fn_ok(move |_: Request<Body>| {
        //             Response::new(Body::from("Success DummyA Server"))
        //         })
        //     })
        //     .map_err(|e| eprintln!("server error: {}", e));
        //     rt::run(server);
        // });

        let conf = Config::new("testdata/passthrough_test.toml").unwrap();
        let srv = passthrough::Server::new(conf.clone(), false);
        let mut lb = srv.lbs[0].clone();

        {
            // set a backend server to healthy
            let mut srvs_map = lb.backend.servers_map.write().unwrap();
            let mut srvs_ring = lb.backend.ring.lock().unwrap();
            let health = srvs_map.get_mut(&SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), 3080)).unwrap();
            *health = true;
            srvs_ring.add_node(&Node{host: IpAddr::V4("127.0.0.1".parse().unwrap()), port: 3080})
        }

        assert_eq!(lb.dsr, false);
        assert_eq!(lb.conn_tracker.lock().unwrap().len(), 0);
        assert_eq!(*lb.backend.servers_map.read().unwrap().get(&SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), 3080)).unwrap(), true);
        assert_eq!(*lb.backend.servers_map.read().unwrap().get(&SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), 3081)).unwrap(), false);

        //TODO: verify messages sent over channel to stats endpoint from proxy
        let (stats_tx, _) = channel();
        thread::spawn( ||{
            srv.run(stats_tx);
        });

        let (tx, _) = channel();
        let dummy_ip = "127.0.0.1".parse().unwrap();

        for i in 0..5 {
            let tx = tx.clone();
            let ip_header = build_dummy_ip(dummy_ip, dummy_ip, 35000 + i, 3000);
            lb.client_handler(&mut ip_header.to_immutable(), tx);
        }

        assert_eq!(lb.conn_tracker.lock().unwrap().len(), 2);
    }

    #[test]
    fn test_passthrough_config_sync() {
        let conf = Config::new("testdata/passthrough_test.toml").unwrap();
        let srv = passthrough::Server::new(conf, false);
        let lb = srv.lbs[0].clone();
        let (tx, _) = channel();
        thread::spawn( ||{
            srv.run(tx);
        });

        let two_sec = time::Duration::from_secs(2);
        thread::sleep(two_sec);

        update_config("testdata/passthrough_test.toml", "127.0.0.1:3080".to_string(), "6.6.6.6:3080".to_string());

        // allow time for updating backend and performing health checks on both servers in config
        let ten_sec = time::Duration::from_secs(10);
        thread::sleep(ten_sec);

        assert_eq!(lb.backend.servers_map.read().unwrap().contains_key(&SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), 3080)), false);
        assert_eq!(*lb.backend.servers_map.read().unwrap().get(&SocketAddr::new(IpAddr::V4("6.6.6.6".parse().unwrap()), 3080)).unwrap(), false);

        // reset fixture
        update_config("testdata/passthrough_test.toml", "6.6.6.6:3080".to_string(), "127.0.0.1:3080".to_string());
    }

    #[test]
    fn test_passthrough_next_port() {
        let conf = Config::new("testdata/passthrough_test.toml").unwrap();
        let srv = passthrough::Server::new(conf, false);
        let mut lb = srv.lbs[0].clone();

        let first_port = lb.next_avail_port();
        assert_eq!(*lb.next_port.lock().unwrap(), first_port);
        assert_eq!(lb.next_avail_port(), first_port + 1);
        *lb.next_port.lock().unwrap() = EPHEMERAL_PORT_UPPER + 1;
        assert_eq!(lb.next_avail_port(), EPHEMERAL_PORT_LOWER);
    }

    #[test]
    fn test_passthrough_server_response() {
        let conf = Config::new("testdata/passthrough_test.toml").unwrap();
        let srv = passthrough::Server::new(conf, false);
        let mut lb = srv.lbs[0].clone();

        let (tx, rx) = channel();
        let lb_ip = "127.0.0.1".parse().unwrap();
        let client_ip: Ipv4Addr = "9.9.9.9".parse().unwrap();
        let backend_srv_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        // simulate response from server at port 80 to local (ephemeral) port 35000
        let resp_header = build_dummy_ip(backend_srv_ip, lb_ip, 80, 35000);
        // server should respond to client ip at client's port
        lb.server_response_handler(&mut resp_header.to_immutable(), &SocketAddr::new(IpAddr::V4(client_ip), 55000), tx);
        let srv_resp: MutableIpv4Packet = rx.recv().unwrap();
        assert_eq!(srv_resp.get_destination(), client_ip);
        assert_eq!(srv_resp.get_source(), lb_ip);

        let tcp_resp = TcpPacket::new(srv_resp.payload()).unwrap();
        assert_eq!(tcp_resp.get_destination(), 55000);
        assert_eq!(tcp_resp.get_source(), 3000);
    }

    #[test]
    fn test_passthrough_client() {
        // load the loadbalancer
        let conf = Config::new("testdata/passthrough_test.toml").unwrap();
        let srv = passthrough::Server::new(conf, false);
        let mut lb = srv.lbs[0].clone();

        let (tx, rx) = channel();
        let lb_ip = "127.0.0.1".parse().unwrap();
        let client_ip: Ipv4Addr = "9.9.9.9".parse().unwrap();
        let backend_srv_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();

        {
            // set a backend server to healthy
            let mut srvs_map = lb.backend.servers_map.write().unwrap();
            let mut srvs_ring = lb.backend.ring.lock().unwrap();
            let health = srvs_map.get_mut(&SocketAddr::new(IpAddr::V4(backend_srv_ip), 3080)).unwrap();
            *health = true;
            srvs_ring.add_node(&Node{host: IpAddr::V4(backend_srv_ip), port: 3080})
        }

        // gen test ip/tcp packet with simulated client
        let req_header = build_dummy_ip(client_ip, lb_ip, 43000, 3000);

        // call client_handler and verify packet being sent out to healthy backend server
        lb.client_handler(&mut req_header.to_immutable(), tx.clone());
        let fwd_pkt: MutableIpv4Packet = rx.recv().unwrap();
        assert_eq!(fwd_pkt.get_destination(), backend_srv_ip);
        assert_eq!(fwd_pkt.get_source(), lb_ip);

        let tcp_resp = TcpPacket::new(fwd_pkt.payload()).unwrap();
        assert_eq!(tcp_resp.get_destination(), 3080);
        assert_eq!(tcp_resp.get_source(), EPHEMERAL_PORT_LOWER + 1);

        {
            // check connection is being tracked
            let port_mp = lb.port_mapper.lock().unwrap();
            let cli = port_mp.get(&(EPHEMERAL_PORT_LOWER + 1)).unwrap();

            let mut test_lb = lb.conn_tracker.lock().unwrap();
            let conn = test_lb.get(&cli).unwrap();
            assert_eq!(conn.ephem_port, EPHEMERAL_PORT_LOWER + 1);
            assert_eq!(conn.client, SocketAddr::new(IpAddr::V4(client_ip), 43000));
        }

        {
            assert_eq!(lb.conn_tracker.lock().unwrap().len(), 1);
        }

        {
            // check same client again to verify connection tracker is used
            lb.client_handler(&mut req_header.to_immutable(), tx.clone());
            // next port should not have incremented
            assert_eq!(*lb.next_port.lock().unwrap(), EPHEMERAL_PORT_LOWER + 1);

            let fwd_pkt: MutableIpv4Packet = rx.recv().unwrap();
            assert_eq!(fwd_pkt.get_destination(), backend_srv_ip);
            assert_eq!(fwd_pkt.get_source(), lb_ip);

            let tcp_resp = TcpPacket::new(fwd_pkt.payload()).unwrap();
            assert_eq!(tcp_resp.get_destination(), 3080);
            assert_eq!(tcp_resp.get_source(), EPHEMERAL_PORT_LOWER + 1);
            assert_eq!(lb.conn_tracker.lock().unwrap().len(), 1);
        }

        {
            // set backend server to unhealthy
            let mut srvs_map = lb.backend.servers_map.write().unwrap();
            let mut srvs_ring = lb.backend.ring.lock().unwrap();
            let health = srvs_map.get_mut(&SocketAddr::new(IpAddr::V4(backend_srv_ip), 3080)).unwrap();
            *health = false;
            srvs_ring.remove_node(&Node{host: IpAddr::V4(backend_srv_ip), port: 3080})
        }

        // check same client again to verify connection is failed
        lb.client_handler(&mut req_header.to_immutable(), tx.clone());
        // since there are not healthy backend servers there should be no connections added to map
        assert_eq!(lb.conn_tracker.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_passthrough_process_packets() {
        // load the loadbalancer
        let conf = Config::new("testdata/passthrough_test.toml").unwrap();
        let srv = passthrough::Server::new(conf, false);
        let lb = srv.lbs[0].clone();

        let (incoming_tx, incoming_rx) = unbounded();
        let (outgoing_tx, outgoing_rx) = channel();
        let (stats_tx, _) = channel();
        let mut thread_lb = lb.clone();
        thread::spawn(move || {
            process_packets(&mut thread_lb, incoming_rx, outgoing_tx, stats_tx);
        });

        let lb_ip = "127.0.0.1".parse().unwrap();
        let client_ip: Ipv4Addr = "9.9.9.9".parse().unwrap();
        let backend_srv_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();

        {
            // set a backend server to healthy
            let mut srvs_map = lb.backend.servers_map.write().unwrap();
            let mut srvs_ring = lb.backend.ring.lock().unwrap();
            let health = srvs_map.get_mut(&SocketAddr::new(IpAddr::V4(backend_srv_ip), 3080)).unwrap();
            *health = true;
            srvs_ring.add_node(&Node{host: IpAddr::V4(backend_srv_ip), port: 3080})
        }

        // simulated client packet
        let test_eth = build_dummy_eth(client_ip, lb_ip, 35000, 3000);
        // send to process packet thread
        incoming_tx.send(EthernetPacket::owned(test_eth.packet().to_owned()).unwrap()).unwrap();

        // read and verify the outgoing processed packet
        let fwd_pkt: MutableIpv4Packet = outgoing_rx.recv().unwrap();
        assert_eq!(fwd_pkt.get_destination(), backend_srv_ip);
        assert_eq!(fwd_pkt.get_source(), lb_ip);

        let tcp_resp = TcpPacket::new(fwd_pkt.payload()).unwrap();
        assert_eq!(tcp_resp.get_destination(), 3080);
        assert_eq!(tcp_resp.get_source(), EPHEMERAL_PORT_LOWER + 1);

        // simulated server response packet from port 3080 to "ephemeral" port mapped to client
        let test_eth = build_dummy_eth(backend_srv_ip, lb_ip, 3080, EPHEMERAL_PORT_LOWER + 1);
        // send to process packet thread
        incoming_tx.send(EthernetPacket::owned(test_eth.packet().to_owned()).unwrap()).unwrap();
        // read and verify the outgoing processed packet
        let fwd_pkt: MutableIpv4Packet = outgoing_rx.recv().unwrap();
        assert_eq!(fwd_pkt.get_destination(), client_ip);
        assert_eq!(fwd_pkt.get_source(), lb_ip);

        let tcp_resp = TcpPacket::new(fwd_pkt.payload()).unwrap();
        // packet should go back to client's actual ephemeral port
        assert_eq!(tcp_resp.get_destination(), 35000);
        assert_eq!(tcp_resp.get_source(), 3000);
    }

    #[test]
    fn test_dsr_process_packets() {
        // load the loadbalancer
        let conf = Config::new("testdata/passthrough_test.toml").unwrap();
        // set dsr flag to true this time
        let srv = passthrough::Server::new(conf, true);
        let lb = srv.lbs[0].clone();

        let (incoming_tx, incoming_rx) = unbounded();
        let (outgoing_tx, outgoing_rx) = channel();
        let (stats_tx, _) = channel();
        let mut thread_lb = lb.clone();
        thread::spawn(move || {
            process_packets(&mut thread_lb, incoming_rx, outgoing_tx, stats_tx);
        });

        let lb_ip = "127.0.0.1".parse().unwrap();
        let client_ip: Ipv4Addr = "9.9.9.9".parse().unwrap();
        let backend_srv_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();

        {
            // set a backend server to healthy
            let mut srvs_map = lb.backend.servers_map.write().unwrap();
            let mut srvs_ring = lb.backend.ring.lock().unwrap();
            let health = srvs_map.get_mut(&SocketAddr::new(IpAddr::V4(backend_srv_ip), 3080)).unwrap();
            *health = true;
            srvs_ring.add_node(&Node{host: IpAddr::V4(backend_srv_ip), port: 3080})
        }

        // simulated client packet
        let test_eth = build_dummy_eth(client_ip, lb_ip, 35000, 3000);
        // send to process packet thread
        incoming_tx.send(EthernetPacket::owned(test_eth.packet().to_owned()).unwrap()).unwrap();

        // read and verify the outgoing processed packet
        let fwd_pkt: MutableIpv4Packet = outgoing_rx.recv().unwrap();
        assert_eq!(fwd_pkt.get_destination(), backend_srv_ip);
        assert_eq!(fwd_pkt.get_source(), client_ip);

        let tcp_resp = TcpPacket::new(fwd_pkt.payload()).unwrap();
        assert_eq!(tcp_resp.get_destination(), 3080);
        assert_eq!(tcp_resp.get_source(), 35000);
    }
}
