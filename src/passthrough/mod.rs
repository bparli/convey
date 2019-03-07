extern crate pnet;
extern crate pnet_macros_support;
extern crate lru_time_cache;

use self::backend::{Backend, ServerPool, Node, health_checker};
use self::arp::Arp;
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
use self::utils::{IPV4_HEADER_LEN, EPHEMERAL_PORT_LOWER, EPHEMERAL_PORT_UPPER, ETHERNET_HEADER_LEN};

mod backend;
mod arp;
mod utils;

//#[derive(Clone)]
pub struct Server {
    // all the loadbalancers in this server.  Should be a 1x1 mapping between the elements in this vector
    // and the "frontends" in the config
    pub lbs: Vec<LB>,

    // the listening end of the configuration sync channel.  New configs trigger this thread to refresh the
    // running config.  Only dynamic backends are supported for now
    config_rx: Receiver<BaseConfig>,
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
    conn_tracker: Arc<RwLock<LruCache<Client, Connection>>>,

    // Port mapper for quickly looking up the client address based on
    // the port a backend server sent a response to.
    // Only used in Passthrough mode without DSR (so bidirectional)
    // Since DSR bypasses coming back through the loadbalancer this data structure
    // isn't needed in Passthrough DSR mode
    port_mapper: Arc<RwLock<HashMap<u16, Client>>>,

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
        let mut lbs = Vec::new();
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
                            conn_tracker: Arc::new(RwLock::new(LruCache::<Client, Connection>::with_capacity(connection_tracker_capacity))),
                            port_mapper: Arc::new(RwLock::new(HashMap::new())),
                            next_port: Arc::new(Mutex::new(EPHEMERAL_PORT_LOWER)),
                            workers: workers,
                            dsr: dsr,
                            stats_update_frequency: stats_update_frequency,
                        };
                        lbs.push(new_lb);
                    }
                    _ => error!("Unable to configure load balancer server {:?}.  Only Ipv4 is supported", front),
                }
            } else {
                error!("Unable to configure load balancer server {:?}", front);
            }
        }
        Server {lbs: lbs, config_rx: config.subscribe()}
    }

    // wait on config changes to update backend server pool
    fn config_sync(&mut self) {
        let mut lbs = self.lbs.clone();
        loop {
            match self.config_rx.recv() {
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
                },
                Err(e) => error!("watch error: {:?}", e),
            }
        }
    }

    pub fn run(&mut self, sender: Sender<StatsMssg>) {
        for lb in self.lbs.iter() {
            let mut srv_thread = lb.clone();
            let thread_sender = sender.clone();
            let _t = thread::spawn(move ||{
                run_server(&mut srv_thread, thread_sender);
            });
        }
        self.config_sync();
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
    fn server_response_handler(&mut self, ip_header: &Ipv4Packet, tcp_header: &mut MutableTcpPacket, client_addr: &SocketAddr, tx: Sender<MutableIpv4Packet>) -> Option<StatsMssg> {
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
    fn client_handler(&mut self, ip_header: &Ipv4Packet, tcp_header: &mut MutableTcpPacket, tx: Sender<MutableIpv4Packet>) -> Option<StatsMssg> {
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

fn find_interface(addr: Ipv4Addr) -> Option<NetworkInterface> {
    let interfaces = datalink::linux::interfaces();
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
fn process_packets(lb: &mut LB, rx: crossbeam_channel::Receiver<EthernetPacket>, tx: Sender<MutableIpv4Packet>, sender: Sender<StatsMssg>, arp_cache: &mut Arp) {
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
                match ethernet.get_ethertype() {
                    EtherTypes::Arp => {
                        arp_cache.handle_arp(&ethernet)
                    }
                    EtherTypes::Ipv4 => {
                        match Ipv4Packet::new(ethernet.payload()) {
                            Some(ip_header) => {
                                if ip_header.get_destination() == lb.listen_ip {
                                    match MutableTcpPacket::new(&mut ip_header.payload().to_vec()) {
                                        Some(mut tcp_header) => {
                                            if tcp_header.get_destination() == lb.listen_port {
                                                if let Some(stats_update) = lb.client_handler(&ip_header, &mut tcp_header, loop_tx.clone()) {
                                                    stats.connections += &stats_update.connections;
                                                    stats.bytes_rx += &stats_update.bytes_rx;
                                                    stats.bytes_tx += &stats_update.bytes_tx;
                                                };
                                            } else if !lb.dsr {
                                                // only handling server repsonses if not using dsr
                                                let guard =  lb.port_mapper.read().unwrap();
                                                let client_addr = guard.get(&tcp_header.get_destination());
                                                match client_addr {
                                                    Some(client_addr) => {
                                                        // drop the lock!
                                                        let cli_socket = &SocketAddr::new( client_addr.ip, client_addr.port);
                                                        std::mem::drop(guard);
                                                        // if true the client socketaddr is in portmapper and the connection/response from backend server is relevant
                                                        if let Some(stats_update) = lb.clone().server_response_handler(&ip_header, &mut tcp_header, cli_socket, loop_tx.clone()) {
                                                            stats.connections += &stats_update.connections;
                                                            stats.bytes_rx += &stats_update.bytes_rx;
                                                            stats.bytes_tx += &stats_update.bytes_tx;
                                                        };
                                                    }
                                                    None => {},
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
                    _ => {}
                }
            }
            Err(e) => error!("Error receiving packet on channel {}", e),
        }
    }
}

pub fn run_server(lb: &mut LB, sender: Sender<StatsMssg>) {
    debug!("Listening for: {:?}, {:?}", lb.listen_ip, lb.listen_port);
    debug!("Load Balancing to: {:?}", lb.backend.name);

    // find local interface we should be listening on
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

    let mut arp_cache = Arp::new(interface.clone(), lb.listen_ip).unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (mut iface_tx, mut iface_rx) = match datalink::linux::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    // multi producer / multi receiver channel for main thread to distribute
    // incoming ethernet packets to multiple workers
    let (incoming_tx, incoming_rx) = unbounded();

    // multi producer / single receiver channel for worker threads to
    // send outgoing ethernet packets
    let (outgoing_tx, outgoing_rx) = channel();

    // spawn the packet processing workers
    for _ in 0..lb.workers {
        let mut thread_lb = lb.clone();
        let thread_rx = incoming_rx.clone();
        let thread_tx = outgoing_tx.clone();
        let thread_sender = sender.clone();
        let mut thread_arp_cache = arp_cache.clone();
        thread::spawn(move || {
            process_packets(&mut thread_lb, thread_rx, thread_tx, thread_sender, &mut thread_arp_cache)
        });
    }

    // start listening before scheduling health checks so we can try catching the ARPs
    // rx thread for receiving ethernet packets
    thread::spawn(move || {
        loop {
            match iface_rx.next() {
                Ok(packet) => {
                    let ethernet = EthernetPacket::owned(packet.to_vec()).unwrap();
                    match incoming_tx.send(ethernet) {
                        Ok(_) => {},
                        Err(e) => error!("Error sending ethernet packet to worker on channel {}", e)
                    }
                }
                Err(e) => {
                    error!("An error occurred while reading: {}", e);
                }
            }
        }
    });

    // spawn background health check thread
    let backend = lb.backend.clone();
    let health_sender = sender.clone();
    let ip = lb.listen_ip;
    thread::spawn( move || {
        loop {
            health_checker(backend.clone(), &health_sender, ip);
            let interval = Duration::from_secs(backend.health_check_interval);
            thread::sleep(interval);
        }
    });

    // make sure we get the default GW HW Address
    let default_gw = arp_cache.default_gw;
    let mut default_gw_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    loop {
        // send arp requests for default gateway before we start processing
        iface_tx.build_and_send(1, 42,
            &mut |eth_packet| {
                let mut eth_packet = MutableEthernetPacket::new(eth_packet).unwrap();

                eth_packet.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
                eth_packet.set_source(interface.mac.unwrap());
                eth_packet.set_ethertype(EtherTypes::Arp);

                let mut arp_buffer = [0u8; 28];
                let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

                arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp_packet.set_protocol_type(EtherTypes::Ipv4);
                arp_packet.set_hw_addr_len(6);
                arp_packet.set_proto_addr_len(4);
                arp_packet.set_operation(ArpOperations::Request);
                arp_packet.set_sender_hw_addr(interface.mac.unwrap());
                arp_packet.set_sender_proto_addr(lb.listen_ip);
                arp_packet.set_target_hw_addr(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
                arp_packet.set_target_proto_addr(default_gw);

                eth_packet.set_payload(arp_packet.packet());

                debug!("Sending eth {:?}", eth_packet)
        });
        // loop until we've received the arp response from the default gateway
        let wait = Duration::from_millis(200);
        thread::sleep(wait);
        if let Some(mac) = arp_cache.clone().get_default_mac() {
            default_gw_mac = mac;
            break
        }
        debug!("Sending another ARP request for Default Gateway's HW Addr");
    }

    // loop in main thread for sending processed packets back out
    loop {
        match outgoing_rx.recv() {
            Ok(ip_header) => {
                let mut target_mac = default_gw_mac;
                if let Some(mac_addr) = arp_cache.get_mac(ip_header.get_destination()) {
                    target_mac = mac_addr;
                } else {
                    error!("Target Mac not in cache, sending to default GW instead");
                    iface_tx.build_and_send(1, 42,
                        &mut |eth_packet| {
                            let mut eth_packet = MutableEthernetPacket::new(eth_packet).unwrap();

                            eth_packet.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
                            eth_packet.set_source(interface.mac.unwrap());
                            eth_packet.set_ethertype(EtherTypes::Arp);

                            let mut arp_buffer = [0u8; 28];
                            let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

                            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                            arp_packet.set_protocol_type(EtherTypes::Ipv4);
                            arp_packet.set_hw_addr_len(6);
                            arp_packet.set_proto_addr_len(4);
                            arp_packet.set_operation(ArpOperations::Request);
                            arp_packet.set_sender_hw_addr(interface.mac.unwrap());
                            arp_packet.set_sender_proto_addr(lb.listen_ip);
                            arp_packet.set_target_hw_addr(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
                            arp_packet.set_target_proto_addr(ip_header.get_destination());

                            eth_packet.set_payload(arp_packet.packet());
                    });
                }

                iface_tx.build_and_send(1, ip_header.packet().len() + ETHERNET_HEADER_LEN,
                    &mut |eth_packet| {
                        let mut eth_packet = MutableEthernetPacket::new(eth_packet).unwrap();

                        eth_packet.set_destination(target_mac);
                        eth_packet.set_source(interface.mac.unwrap());
                        eth_packet.set_ethertype(EtherTypes::Ipv4);
                        eth_packet.set_payload(&ip_header.packet());

                        debug!("Sending eth {:?}", eth_packet)
                });
            }
            Err(e) => error!("Error processing outgoing packet {:?}", e),
        }
    }
}


#[cfg(test)]
mod tests {
    extern crate hyper;
    use std::sync::mpsc::channel;
    use std::thread;
    use crate::config::{Config};
    use crate::passthrough;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::{time};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use self::passthrough::utils::{EPHEMERAL_PORT_LOWER, EPHEMERAL_PORT_UPPER, build_dummy_eth, build_dummy_ip};
    use self::passthrough::{Node, process_packets, find_interface};
    use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
    use pnet::packet::ipv4::{MutableIpv4Packet};
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::Packet;
    use crossbeam_channel::unbounded;
    use self::passthrough::arp::Arp;

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
        let conf = Config::new("testdata/passthrough_test.toml").unwrap();
        let mut srv = passthrough::Server::new(conf.clone(), false);
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
        assert_eq!(lb.conn_tracker.read().unwrap().len(), 0);
        assert_eq!(*lb.backend.servers_map.read().unwrap().get(&SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), 3080)).unwrap(), true);
        assert_eq!(*lb.backend.servers_map.read().unwrap().get(&SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), 3081)).unwrap(), false);

        //TODO: verify messages sent over channel to stats endpoint from proxy
        let (stats_tx, _) = channel();
        thread::spawn(move ||{
            srv.run(stats_tx);
        });

        let (tx, _) = channel();
        let dummy_ip = "127.0.0.1".parse().unwrap();

        for i in 0..5 {
            let tx = tx.clone();
            let ip_header = build_dummy_ip(dummy_ip, dummy_ip, 35000 + i, 3000);
            let mut tcp_header = MutableTcpPacket::owned(ip_header.payload().to_owned()).unwrap();
            lb.client_handler(&mut ip_header.to_immutable(), &mut tcp_header, tx);
        }

        assert_eq!(lb.conn_tracker.read().unwrap().len(), 2);
    }

    #[test]
    fn test_passthrough_config_sync() {
        let conf = Config::new("testdata/passthrough_test.toml").unwrap();
        let mut srv = passthrough::Server::new(conf, false);
        let lb = srv.lbs[0].clone();
        let (tx, _) = channel();
        thread::spawn(move ||{
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
        let mut tcp_header = MutableTcpPacket::owned(resp_header.payload().to_owned()).unwrap();
        // server should respond to client ip at client's port
        lb.server_response_handler(&resp_header.to_immutable(), &mut tcp_header, &SocketAddr::new(IpAddr::V4(client_ip), 55000), tx);
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
        let mut tcp_header = MutableTcpPacket::owned(req_header.payload().to_owned()).unwrap();

        // call client_handler and verify packet being sent out to healthy backend server
        lb.client_handler(&mut req_header.to_immutable(), &mut tcp_header, tx.clone());
        let fwd_pkt: MutableIpv4Packet = rx.recv().unwrap();
        assert_eq!(fwd_pkt.get_destination(), backend_srv_ip);
        assert_eq!(fwd_pkt.get_source(), lb_ip);

        let tcp_resp = TcpPacket::new(fwd_pkt.payload()).unwrap();
        assert_eq!(tcp_resp.get_destination(), 3080);
        assert_eq!(tcp_resp.get_source(), EPHEMERAL_PORT_LOWER + 1);

        {
            // check connection is being tracked
            let port_mp = lb.port_mapper.read().unwrap();
            let cli = port_mp.get(&(EPHEMERAL_PORT_LOWER + 1)).unwrap();

            let mut test_lb = lb.conn_tracker.write().unwrap();
            let conn = test_lb.get(&cli).unwrap();
            assert_eq!(conn.ephem_port, EPHEMERAL_PORT_LOWER + 1);
            assert_eq!(conn.client, SocketAddr::new(IpAddr::V4(client_ip), 43000));
        }

        {
            assert_eq!(lb.conn_tracker.read().unwrap().len(), 1);
        }

        {
            // check same client again to verify connection tracker is used
            let mut tcp_header = MutableTcpPacket::owned(req_header.payload().to_owned()).unwrap();
            lb.client_handler(&mut req_header.to_immutable(), &mut tcp_header, tx.clone());
            // next port should not have incremented
            assert_eq!(*lb.next_port.lock().unwrap(), EPHEMERAL_PORT_LOWER + 1);

            let fwd_pkt: MutableIpv4Packet = rx.recv().unwrap();
            assert_eq!(fwd_pkt.get_destination(), backend_srv_ip);
            assert_eq!(fwd_pkt.get_source(), lb_ip);

            let tcp_resp = TcpPacket::new(fwd_pkt.payload()).unwrap();
            assert_eq!(tcp_resp.get_destination(), 3080);
            assert_eq!(tcp_resp.get_source(), EPHEMERAL_PORT_LOWER + 1);
            assert_eq!(lb.conn_tracker.read().unwrap().len(), 1);
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
        let mut tcp_header = MutableTcpPacket::owned(req_header.payload().to_owned()).unwrap();
        lb.client_handler(&mut req_header.to_immutable(), &mut tcp_header, tx.clone());
        // since there are not healthy backend servers there should be no connections added to map
        assert_eq!(lb.conn_tracker.read().unwrap().len(), 0);
    }

    #[test]
    fn test_passthrough_process_packets() {
        // load the loadbalancer
        let conf = Config::new("testdata/passthrough_test.toml").unwrap();
        let srv = passthrough::Server::new(conf, false);
        let lb = srv.lbs[0].clone();

        let lb_ip = "127.0.0.1".parse().unwrap();
        let interface = find_interface(lb_ip).unwrap();
        let mut arp_cache = Arp::new(interface, lb_ip).unwrap();

        let (incoming_tx, incoming_rx) = unbounded();
        let (outgoing_tx, outgoing_rx) = channel();
        let (stats_tx, _) = channel();
        let mut thread_lb = lb.clone();
        thread::spawn(move || {
            process_packets(&mut thread_lb, incoming_rx, outgoing_tx, stats_tx, &mut arp_cache);
        });


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

        let lb_ip = "127.0.0.1".parse().unwrap();
        let interface = find_interface(lb_ip).unwrap();
        let mut arp_cache = Arp::new(interface, lb_ip).unwrap();

        let lb_ip = "127.0.0.1".parse().unwrap();
        let (incoming_tx, incoming_rx) = unbounded();
        let (outgoing_tx, outgoing_rx) = channel();
        let (stats_tx, _) = channel();
        let mut thread_lb = lb.clone();
        thread::spawn(move || {
            process_packets(&mut thread_lb, incoming_rx, outgoing_tx, stats_tx, &mut arp_cache);
        });

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
