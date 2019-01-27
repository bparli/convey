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
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::datalink::Channel::Ethernet;
use std::sync::{Arc, Mutex};
use std::net::{SocketAddr};
use std::str::FromStr;
use std::sync::mpsc::{Sender, Receiver, channel};
use std::collections::HashMap;
use std::{thread};
use threadpool::ThreadPool;
use lru_time_cache::LruCache;
use tokio::prelude::*;
use tokio::timer::Interval;
use std::time::{Duration, Instant};
use futures::future::lazy;

const IPV4_HEADER_LEN: usize = 20;
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
    client: SocketAddr,
    backend_srv: Node,
    ephem_port: u16,
}

struct Transmit {
    ip_packet: Vec<u8>,
    ip_addr: IpAddr,
    frontend_name: String,
    backend_name: String,
    connections: i32,
    from_client: bool,
    from_server: bool,
}

#[derive(Clone)]
pub struct LB {
    name: String,

    listen_ip: Ipv4Addr,

    listen_port: u16,

    backend: Arc<Backend>,

    conn_tracker: Arc<Mutex<LruCache<Client, Connection>>>,

    port_mapper: Arc<Mutex<HashMap<u16, Client>>>,

    next_port: Arc<Mutex<u16>>,

    workers: usize,

    dsr: bool
}

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

            match config.base.passthrough {
                Some(setting) => {
                    connection_tracker_capacity = setting.connection_tracker_capacity;
                    if let Some(num) = setting.workers {
                        workers = num;
                    }
                    if let Some(flag) = setting.dsr {
                        dsr = flag;
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

    fn server_response_handler(&mut self, ip_header: Ipv4Packet, client_addr: &SocketAddr, tx: Sender<Transmit>) {
        let tcp_header = match TcpPacket::new(ip_header.payload()) {
            Some(tcp_header) => tcp_header,
            None => {
                error!("Unable to decapsulate tcp header");
                return
            }
        };

        match client_addr.ip() {
            IpAddr::V4(client_ipv4) => {
                let vec: Vec<u8> = vec![0; tcp_header.packet().len()];
                let mut new_tcp = MutableTcpPacket::owned(vec).unwrap();
                new_tcp.clone_from(&tcp_header);

                let ipbuf: Vec<u8> = vec!(0; new_tcp.packet().len() + IPV4_HEADER_LEN);
                let mut new_ipv4 = MutableIpv4Packet::owned(ipbuf).unwrap();
                new_ipv4.clone_from(&ip_header);
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

                let mut connections = 0;
                match tcp_header.get_flags() {
                    0b000010010 => connections = 1, // add a connection to count on SYN,ACK
                    0b000010001 => connections = -1, // sub a connection to count on FIN,ACK
                    _ => {},
                }

                let transmit = Transmit{
                    ip_packet: new_ipv4.packet().to_owned(),
                    ip_addr: client_addr.ip(),
                    frontend_name: self.name.clone(),
                    backend_name: self.backend.name.clone(),
                    connections: connections,
                    from_client: false,
                    from_server: true,
                };
                tx.send(transmit).unwrap();
            }
            _ => {} // ipv6 not supported (yet)
        }
    }

    fn client_handler(&mut self, ip_header: Ipv4Packet, tx: Sender<Transmit>) {
        let tcp_header = match TcpPacket::new(ip_header.payload()) {
            Some(tcp_header) => tcp_header,
            None => {
                error!("Unable to decapsulate tcp header");
                return
            }
        };

        // setup forwarding packet
        let vec: Vec<u8> = vec![0; tcp_header.packet().len()];
        let mut new_tcp = MutableTcpPacket::owned(vec).unwrap();
        new_tcp.clone_from(&tcp_header);
        let ipbuf: Vec<u8> = vec!(0; tcp_header.packet().len() + IPV4_HEADER_LEN);
        let mut new_ipv4 = MutableIpv4Packet::owned(ipbuf).unwrap();

        new_ipv4.clone_from(&ip_header);
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
                        // leave original tcp source if dsr
                        if !self.dsr {
                            new_tcp.set_source(conn.ephem_port);
                        }

                        new_tcp.set_destination(conn.backend_srv.port);
                        new_tcp.set_checksum(tcp::ipv4_checksum(&new_tcp.to_immutable(), &self.listen_ip, &fwd_ipv4));

                        new_ipv4.set_payload(&new_tcp.packet());
                        new_ipv4.set_destination(fwd_ipv4);
                        new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));

                        let transmit = Transmit{
                            ip_packet: new_ipv4.packet().to_owned(),
                            ip_addr: conn.backend_srv.host.clone(),
                            frontend_name: self.name.clone(),
                            backend_name: self.backend.name.clone(),
                            connections: 0,
                            from_client: true,
                            from_server: false,
                        };

                        tx.send(transmit).unwrap();
                        return
                    } else {
                        debug!("Backend sever {:?} is no longer healthy.  Rescheduling", conn.backend_srv);
                        // backend server is unhealthy, remove connection from map
                        // leave in port_mapper in case there are still packets from server in flight
                        cli_unhealthy = true;
                    }
                }
                _ => {}
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
                    }

                    new_tcp.set_destination(node.port);
                    new_tcp.set_checksum(tcp::ipv4_checksum(&new_tcp.to_immutable(), &self.listen_ip, &fwd_ipv4));

                    new_ipv4.set_payload(&new_tcp.packet());
                    new_ipv4.set_destination(fwd_ipv4);
                    new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));

                    let transmit = Transmit{
                        ip_packet: new_ipv4.packet().to_owned(),
                        ip_addr: node.host.clone(),
                        frontend_name: self.name.clone(),
                        backend_name: self.backend.name.clone(),
                        connections: 0,
                        from_client: true,
                        from_server: false,
                    };
                    tx.send(transmit).unwrap();

                    // not already tracking the connection so insert into our maps
                    let conn = Connection {
                        client: SocketAddr::new(IpAddr::V4(ip_header.get_source()), tcp_header.get_source()),
                        backend_srv: node,
                        ephem_port: ephem_port,
                    };
                    self.conn_tracker.lock().unwrap().insert(cli, conn);
                }
                _ => {}
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

            let transmit = Transmit{
                ip_packet: new_ipv4.packet().to_owned(),
                ip_addr: cli.ip,
                frontend_name: self.name.clone(),
                backend_name: self.backend.name.clone(),
                connections: -1,
                from_client: true,
                from_server: false,
            };
            tx.send(transmit).unwrap();
        }
    }

    fn cli_connection(&mut self, cli: &Client) -> Option<Connection>{
        if let Some(conn) = self.conn_tracker.lock().unwrap().get(&cli) {
            return Some(conn.clone());
        }
        None
    }
}

fn transmitter (channel_rx: Receiver<Transmit>, sender: Sender<StatsMssg>) {
    let tx_protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tx, _) = match transport_channel(4096, tx_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            error!("Error setting up transmission channel thread {}", e);
            return
        },
    };

    loop {
        match channel_rx.recv() {
            Ok(new_packet) => {
                if let Some(pckt) = Ipv4Packet::new(&new_packet.ip_packet) {
                    match tx.send_to(pckt, new_packet.ip_addr) {
                        Ok(n) => {
                            debug!("Sent {} bytes to Server", n);
                            let (mut bytes_rx, mut bytes_tx) = (0, 0);
                            if new_packet.from_client {
                                bytes_tx = n;
                            } else if new_packet.from_server {
                                bytes_rx = n;
                            }
                            let mssg = StatsMssg{frontend: Some(new_packet.frontend_name),
                                                backend: new_packet.backend_name,
                                                connections: new_packet.connections,
                                                bytes_tx: bytes_tx as u64,
                                                bytes_rx: bytes_rx as u64,
                                                servers: None};
                            match sender.send(mssg) {
                                Ok(_) => {},
                                Err(e) => error!("Error sending stats message on channel: {}", e)
                            }
                        },
                        Err(e) => error!("failed to send packet: {}", e),
                    }
                } else {
                    error!("Transmitter thread received bd packet {:?}", &new_packet.ip_packet);
                }
            }
            Err(e) => error!("failed to receive new packet on transmitter thread: {}", e),
        }
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

fn process_packets(lb: &mut LB, ip_header: Ipv4Packet, tx: Sender<Transmit>) {
    match TcpPacket::new(ip_header.payload()) {
        Some(tcp_header) => {
            if tcp_header.get_destination() == lb.listen_port {
                lb.client_handler(ip_header, tx);
            } else if !lb.dsr {
                // only handling server repsonses if not using dsr
                if let Some(client_addr) = lb.port_mapper.lock().unwrap().get_mut(&tcp_header.get_destination()) {
                    // if true the client socketaddr is in portmapper and the connection/response from backend server is relevant
                    lb.clone().server_response_handler(ip_header, &SocketAddr::new( client_addr.ip, client_addr.port), tx);
                }
            }
        }
        None => {},
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
            info!("Listening on interface {}", interface);
            interface
        }
        None => {
            error!("Unable to find network interface with IP {:?}.  Skipping {}", lb.listen_ip, lb.name);
            return
        }
    };

    // Create a new channel, dealing with layer 2 packets
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    let tpool = ThreadPool::new(lb.workers);

    let tx_protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (tx, _) = match transport_channel(4096, tx_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            error!("Error {}", e);
            return
        },
    };

    let threads_tx = Arc::new(Mutex::new(tx));

    let (channel_tx, channel_rx) = channel();
    thread::spawn(move || {
        transmitter(channel_rx, sender)
    });

    loop {
        match rx.next() {
            Ok(packet) => {
                if !interface.is_loopback() {
                    let ethernet = EthernetPacket::new(packet).unwrap();
                    match ethernet.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            match Ipv4Packet::owned(ethernet.payload().iter().cloned().collect()) {
                                Some(ip_header) => {
                                    let ip_addr = ip_header.get_destination();
                                    if ip_addr == lb.listen_ip {
                                        let mut thread_lb = lb.clone();
                                        let thread_tx = channel_tx.clone();
                                        //let thread_sender = sender.clone();
                                        tpool.execute(move|| {
                                            process_packets(&mut thread_lb, ip_header, thread_tx);
                                        });
                                    }
                                },
                                None => {},
                            }
                        }
                        _ => {}
                    }
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
