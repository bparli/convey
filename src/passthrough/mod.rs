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
use std::sync::mpsc::{Sender, Receiver};
use std::collections::HashMap;
use std::{thread};
use threadpool::ThreadPool;
use lru_time_cache::LruCache;
use tokio::prelude::*;
use tokio::timer::Interval;
use std::time::{Duration, Instant};
use futures::future::lazy;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
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

#[derive(Clone)]
pub struct LB {
    name: String,

    listen_ip: Ipv4Addr,

    listen_port: u16,

    backend: Arc<Backend>,

    conn_tracker: Arc<Mutex<LruCache<Client, Connection>>>,

    port_mapper: Arc<Mutex<LruCache<u16, Client>>>,

    next_port: Arc<Mutex<u16>>
}

impl Server {
    pub fn new(config: Config) -> Server {
        let mut new_server = Server {lbs: Vec::new()};
        for (name,front) in config.base.frontends.iter() {
            let mut backend_servers = HashMap::new();
            let mut health_check_interval = 5;
            let mut connection_tracker_capacity = 1000 as usize;

            match config.base.passthrough {
                Some(setting) => connection_tracker_capacity = setting.connection_tracker_capacity,
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
                            port_mapper: Arc::new(Mutex::new(LruCache::<u16, Client>::with_capacity(connection_tracker_capacity))),
                            next_port: Arc::new(Mutex::new(EPHEMERAL_PORT_LOWER)),
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
        let lbs = self.lbs.clone();
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
                            let new_server_pool = ServerPool::new_servers(backend_servers);
                            for lb in lbs.iter() {
                                if lb.backend.name == backend_name {
                                    info!("Updating backend {} with {:?}", backend_name, new_server_pool);
                                    *lb.backend.servers.write().unwrap() = new_server_pool.clone();
                                }
                            }
                        }
                    }
                    Err(e) => error!("watch error: {:?}", e),
                }
            }
        });
    }

    pub fn run(self, sender: Sender<StatsMssg>, workers: u64) {
        let mut threads = Vec::new();
        for lb in self.lbs.iter() {
            let srv_thread = lb.clone();
            let thread_sender = sender.clone();
            let t = thread::spawn(move ||{
                run_server(srv_thread, thread_sender, workers)
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

    fn server_response_handler(&mut self, ip_header: Ipv4Packet, client_addr: &SocketAddr, tx: Arc<Mutex<TransportSender>>) {
        let tcp_header = match TcpPacket::new(ip_header.payload()) {
            Some(tcp_header) => tcp_header,
            None => {
                error!("Unable to decapsulate tcp header");
                return
            }
        };

        match client_addr.ip() {
            IpAddr::V4(client_ipv4) => {
                let mut vec: Vec<u8> = vec![0; tcp_header.packet().len()];
                let mut new_tcp = MutableTcpPacket::new(&mut vec[..]).unwrap();
                new_tcp.clone_from(&tcp_header);

                let mut ipbuf = vec!(0; new_tcp.packet().len() + IPV4_HEADER_LEN);
                let mut new_ipv4 = MutableIpv4Packet::new(&mut ipbuf).unwrap();
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

                match tx.lock().unwrap().send_to(new_ipv4, client_addr.ip()) {
                    Ok(n) => debug!("Sent {} bytes to Client", n),
                    Err(e) => debug!("failed to send packet to {:?}: Error: {}", client_addr, e),
                }
            }
            _ => {} // ipv6 not supported (yet)
        }
    }

    fn client_handler(&mut self, ip_header: Ipv4Packet, tx: Arc<Mutex<TransportSender>>) {
        let tcp_header = match TcpPacket::new(ip_header.payload()) {
            Some(tcp_header) => tcp_header,
            None => {
                error!("Unable to decapsulate tcp header");
                return
            }
        };

        // setup forwarding packet
        let mut vec: Vec<u8> = vec![0; tcp_header.packet().len()];
        let mut new_tcp = MutableTcpPacket::new(&mut vec[..]).unwrap();
        new_tcp.clone_from(&tcp_header);
        let mut ipbuf = vec!(0; tcp_header.packet().len() + IPV4_HEADER_LEN);
        let mut new_ipv4 = MutableIpv4Packet::new(&mut ipbuf).unwrap();
        new_ipv4.clone_from(&ip_header);
        new_ipv4.set_total_length(tcp_header.packet().len() as u16 + IPV4_HEADER_LEN as u16);
        new_ipv4.set_version(4);
        new_ipv4.set_ttl(225);
        new_ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        new_ipv4.set_source(self.listen_ip);
        new_ipv4.set_header_length(5);

        // check if we are already tracking this connection
        let cli = Client{
            ip: IpAddr::V4(ip_header.get_source()),
            port: tcp_header.get_source(),
        };
        let mut connections = self.conn_tracker.lock().unwrap();
        if let Some(conn) = connections.get(&cli) {
            match conn.backend_srv.host {
                IpAddr::V4(fwd_ipv4) => {

                    new_tcp.set_source(conn.ephem_port);
                    new_tcp.set_destination(conn.backend_srv.port);
                    new_tcp.set_checksum(tcp::ipv4_checksum(&new_tcp.to_immutable(), &self.listen_ip, &fwd_ipv4));

                    new_ipv4.set_payload(&new_tcp.packet());
                    new_ipv4.set_destination(fwd_ipv4);
                    new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));

                    match tx.lock().unwrap().send_to(new_ipv4, conn.backend_srv.host) {
                        Ok(n) => debug!("Sent {} bytes to Server", n),
                        Err(e) => debug!("failed to send packet: {}", e),
                    }

                }
                _ => {}
            }
        } else {
            if let Some(node) = self.backend.get_server(IpAddr::V4(self.listen_ip), self.listen_port, IpAddr::V4(ip_header.get_source()), tcp_header.get_source()) {
                match node.host {
                    IpAddr::V4(fwd_ipv4) => {

                        // set ephemeral port for tracking connections and in case of mutiple clients using same port
                        let ephem_port: u16 = self.clone().next_avail_port();
                        debug!("Using Ephemeral port {} for client connection {:?}", ephem_port, SocketAddr::new(IpAddr::V4(ip_header.get_source()), tcp_header.get_source()));
                        {
                            self.port_mapper.lock().unwrap().insert(ephem_port, Client{ip: IpAddr::V4(ip_header.get_source()), port: tcp_header.get_source()});
                        }

                        new_tcp.set_source(ephem_port);
                        new_tcp.set_destination(node.port);
                        new_tcp.set_checksum(tcp::ipv4_checksum(&new_tcp.to_immutable(), &self.listen_ip, &fwd_ipv4));

                        new_ipv4.set_payload(&new_tcp.packet());
                        new_ipv4.set_destination(fwd_ipv4);
                        new_ipv4.set_checksum(checksum(&new_ipv4.to_immutable()));

                        match tx.lock().unwrap().send_to(new_ipv4, node.host) {
                            Ok(n) => debug!("Sent {} bytes to Server", n),
                            Err(e) => debug!("failed to send packet: {}", e),
                        }

                        // not already tracking the connection so insert into our maps
                        let conn = Connection {
                            client: SocketAddr::new(IpAddr::V4(ip_header.get_source()), tcp_header.get_source()),
                            backend_srv: node,
                            ephem_port: ephem_port,
                        };

                        connections.insert(cli, conn);
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

                match tx.lock().unwrap().send_to(new_ipv4, cli.ip) {
                    Ok(n) => debug!("Sent {} bytes to Client", n),
                    Err(e) => debug!("failed to send packet: {}", e),
                }
            }
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

fn process_packets(lb: &mut LB, ip_header: Ipv4Packet, tx: Arc<Mutex<TransportSender>>) {
    match TcpPacket::new(ip_header.payload()) {
        Some(tcp_header) => {
            if tcp_header.get_destination() == lb.listen_port {
                lb.client_handler(ip_header, tx);
            } else {
                // hack to workaround borrowing lb twice
                let mut server_process = false;
                let mut addr = SocketAddr::new( IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

                if let Some(client_addr) = lb.port_mapper.lock().unwrap().get_mut(&tcp_header.get_destination()) {
                    addr = SocketAddr::new( client_addr.ip, client_addr.port);
                    server_process = true;
                }
                // if true the client socketaddr is in portmapper and the connection/response from backend server is relevant
                if server_process {
                    lb.server_response_handler(ip_header, &addr, tx);
                }
            }
        }
        None => {},
    }
}

pub fn run_server(lb: LB, sender: Sender<StatsMssg>, workers: u64) {
    debug!("Listening for: {:?}, {:?}", lb.listen_ip, lb.listen_port);
    debug!("Load Balancing to: {:?}", lb.backend.name);

    let backend = lb.backend.clone();
    thread::spawn( move || {
        sched_health_checks(backend, sender.clone());
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

    let tpool = ThreadPool::new(workers as usize);

    let tx_protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (tx, _) = match transport_channel(4096, tx_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            error!("Error {}", e);
            return
        },
    };

    let threads_tx = Arc::new(Mutex::new(tx));

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
                                        let thread_tx = threads_tx.clone();
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
