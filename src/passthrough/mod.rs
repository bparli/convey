extern crate lru_time_cache;
extern crate pnet;
extern crate pnet_macros_support;

use self::arp::Arp;
use self::backend::{health_checker, ServerPool};
use self::lb::LB;
use self::utils::{find_interface, ETHERNET_HEADER_LEN};

use crate::config::{BaseConfig, Config};
use crate::stats::StatsMssg;
use crossbeam_channel::unbounded;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;

mod arp;
mod backend;
mod lb;
mod utils;

pub struct Server {
    // all the loadbalancers in this server.  Should be a 1x1 mapping between the elements in this vector
    // and the "frontends" in the config
    pub lbs: Vec<LB>,

    // the listening end of the configuration sync channel.  New configs trigger this thread to refresh the
    // running config.  Only dynamic backends are supported for now
    config_rx: Receiver<BaseConfig>,
}

// Server is the overarching type, comprised of at least one loadbalancer
impl Server {
    pub fn new(config: Config, dsr: bool) -> Server {
        let mut lbs = Vec::new();
        for (name, _) in config.base.frontends.iter() {
            if let Some(new_lb) = LB::new(name.to_string(), config.clone(), dsr) {
                lbs.push(new_lb);
            }
        }
        Server {
            lbs: lbs,
            config_rx: config.subscribe(),
        }
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
                                debug!(
                                    "Updating backend {} with {:?}",
                                    backend_name,
                                    backend_servers.clone()
                                );
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
    }

    pub fn run(&mut self, sender: Sender<StatsMssg>) {
        for lb in self.lbs.iter() {
            let mut srv_thread = lb.clone();
            let thread_sender = sender.clone();
            let _t = thread::spawn(move || {
                run_server(&mut srv_thread, thread_sender);
            });
        }
        self.config_sync();
    }
}

// worker thread
fn process_packets(
    lb: &mut LB,
    rx: crossbeam_channel::Receiver<EthernetPacket>,
    tx: Sender<MutableIpv4Packet>,
    sender: Sender<StatsMssg>,
    arp_cache: &mut Arp,
) {
    let mut stats = StatsMssg {
        frontend: Some(lb.name.clone()),
        backend: lb.backend.name.clone(),
        connections: 0,
        bytes_tx: 0,
        bytes_rx: 0,
        servers: None,
    };

    // Spawn timer for sending stats updates
    let (stats_tx, stats_rx) = channel();
    let freq = lb.stats_update_frequency;
    thread::spawn(move || loop {
        stats_tx.send("tick").unwrap();
        thread::sleep(Duration::from_secs(freq));
    });

    let loop_tx = tx.clone();
    loop {
        match rx.recv() {
            Ok(ethernet) => {
                match ethernet.get_ethertype() {
                    EtherTypes::Arp => arp_cache.handle_arp(&ethernet),
                    EtherTypes::Ipv4 => {
                        match Ipv4Packet::new(ethernet.payload()) {
                            Some(ip_header) => {
                                if ip_header.get_destination() == lb.listen_ip {
                                    match MutableTcpPacket::new(&mut ip_header.payload().to_vec()) {
                                        Some(mut tcp_header) => {
                                            if tcp_header.get_destination() == lb.listen_port {
                                                if let Some(stats_update) = lb.client_handler(
                                                    &ip_header,
                                                    &mut tcp_header,
                                                    loop_tx.clone(),
                                                ) {
                                                    stats.connections += &stats_update.connections;
                                                    stats.bytes_rx += &stats_update.bytes_rx;
                                                    stats.bytes_tx += &stats_update.bytes_tx;
                                                };
                                            } else if !lb.dsr {
                                                // only handling server repsonses if not using dsr
                                                let guard = lb.port_mapper.read().unwrap();
                                                let client_addr =
                                                    guard.get(&tcp_header.get_destination());
                                                match client_addr {
                                                    Some(client_addr) => {
                                                        // drop the lock!
                                                        let cli_socket = &SocketAddr::new(
                                                            client_addr.ip,
                                                            client_addr.port,
                                                        );
                                                        std::mem::drop(guard);
                                                        // if true the client socketaddr is in portmapper and the connection/response from backend server is relevant
                                                        if let Some(stats_update) =
                                                            lb.clone().server_response_handler(
                                                                &ip_header,
                                                                &mut tcp_header,
                                                                cli_socket,
                                                                loop_tx.clone(),
                                                            )
                                                        {
                                                            stats.connections +=
                                                                &stats_update.connections;
                                                            stats.bytes_rx +=
                                                                &stats_update.bytes_rx;
                                                            stats.bytes_tx +=
                                                                &stats_update.bytes_tx;
                                                        };
                                                    }
                                                    None => {}
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
                                                Err(_) => {}
                                            }
                                        }
                                        None => {}
                                    }
                                }
                            }
                            None => {}
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
                return;
            }
            println!("Listening on interface {}", interface);
            interface
        }
        None => {
            error!(
                "Unable to find network interface with IP {:?}.  Skipping {}",
                lb.listen_ip, lb.name
            );
            return;
        }
    };

    let mut arp_cache = Arp::new(interface.clone(), lb.listen_ip).unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (mut iface_tx, mut iface_rx) =
        match datalink::linux::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
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
            process_packets(
                &mut thread_lb,
                thread_rx,
                thread_tx,
                thread_sender,
                &mut thread_arp_cache,
            )
        });
    }

    // start listening before scheduling health checks so we can try catching the ARPs
    // rx thread for receiving ethernet packets
    thread::spawn(move || loop {
        match iface_rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::owned(packet.to_vec()).unwrap();
                match incoming_tx.send(ethernet) {
                    Ok(_) => {}
                    Err(e) => error!("Error sending ethernet packet to worker on channel {}", e),
                }
            }
            Err(e) => {
                error!("An error occurred while reading: {}", e);
            }
        }
    });

    // spawn background health check thread
    let backend = lb.backend.clone();
    let health_sender = sender.clone();
    let ip = lb.listen_ip;
    thread::spawn(move || loop {
        health_checker(backend.clone(), &health_sender, ip);
        let interval = Duration::from_secs(backend.health_check_interval);
        thread::sleep(interval);
    });

    // make sure we get the default GW HW Address
    let default_gw = arp_cache.default_gw;
    let default_gw_mac: MacAddr;
    loop {
        // send arp requests for default gateway before we start processing
        iface_tx.build_and_send(1, 42, &mut |eth_packet| {
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
            break;
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
                    iface_tx.build_and_send(1, 42, &mut |eth_packet| {
                        let mut eth_packet = MutableEthernetPacket::new(eth_packet).unwrap();

                        eth_packet
                            .set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
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
                        arp_packet
                            .set_target_hw_addr(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
                        arp_packet.set_target_proto_addr(ip_header.get_destination());

                        eth_packet.set_payload(arp_packet.packet());
                    });
                }

                iface_tx.build_and_send(
                    1,
                    ip_header.packet().len() + ETHERNET_HEADER_LEN,
                    &mut |eth_packet| {
                        let mut eth_packet = MutableEthernetPacket::new(eth_packet).unwrap();

                        eth_packet.set_destination(target_mac);
                        eth_packet.set_source(interface.mac.unwrap());
                        eth_packet.set_ethertype(EtherTypes::Ipv4);
                        eth_packet.set_payload(&ip_header.packet());

                        debug!("Sending eth {:?}", eth_packet)
                    },
                );
            }
            Err(e) => error!("Error processing outgoing packet {:?}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate hyper;
    use self::passthrough::arp::Arp;
    use self::passthrough::backend::Node;
    use self::passthrough::utils::{build_dummy_eth, build_dummy_ip, EPHEMERAL_PORT_LOWER};
    use self::passthrough::{find_interface, process_packets};
    use crate::config::Config;
    use crate::passthrough;
    use crossbeam_channel::unbounded;
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
    use pnet::packet::Packet;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::mpsc::channel;
    use std::thread;
    use std::time;

    fn update_config(filename: &str, word_from: String, word_to: String) {
        let mut src = File::open(&filename).unwrap();
        let mut data = String::new();
        src.read_to_string(&mut data).unwrap();
        drop(src); // Close the file early

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
            let health = srvs_map
                .get_mut(&SocketAddr::new(
                    IpAddr::V4("127.0.0.1".parse().unwrap()),
                    3080,
                ))
                .unwrap();
            *health = true;
            srvs_ring.add_node(&Node {
                host: IpAddr::V4("127.0.0.1".parse().unwrap()),
                port: 3080,
            })
        }

        assert_eq!(lb.dsr, false);
        assert_eq!(lb.conn_tracker.read().unwrap().len(), 0);
        assert_eq!(
            *lb.backend
                .servers_map
                .read()
                .unwrap()
                .get(&SocketAddr::new(
                    IpAddr::V4("127.0.0.1".parse().unwrap()),
                    3080
                ))
                .unwrap(),
            true
        );
        assert_eq!(
            *lb.backend
                .servers_map
                .read()
                .unwrap()
                .get(&SocketAddr::new(
                    IpAddr::V4("127.0.0.1".parse().unwrap()),
                    3081
                ))
                .unwrap(),
            false
        );

        //TODO: verify messages sent over channel to stats endpoint from proxy
        let (stats_tx, _) = channel();
        thread::spawn(move || {
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
        thread::spawn(move || {
            srv.run(tx);
        });

        let two_sec = time::Duration::from_secs(2);
        thread::sleep(two_sec);

        update_config(
            "testdata/passthrough_test.toml",
            "127.0.0.1:3080".to_string(),
            "6.6.6.6:3080".to_string(),
        );

        // allow time for updating backend and performing health checks on both servers in config
        let ten_sec = time::Duration::from_secs(10);
        thread::sleep(ten_sec);

        assert_eq!(
            lb.backend
                .servers_map
                .read()
                .unwrap()
                .contains_key(&SocketAddr::new(
                    IpAddr::V4("127.0.0.1".parse().unwrap()),
                    3080
                )),
            false
        );
        assert_eq!(
            *lb.backend
                .servers_map
                .read()
                .unwrap()
                .get(&SocketAddr::new(
                    IpAddr::V4("6.6.6.6".parse().unwrap()),
                    3080
                ))
                .unwrap(),
            false
        );

        // reset fixture
        update_config(
            "testdata/passthrough_test.toml",
            "6.6.6.6:3080".to_string(),
            "127.0.0.1:3080".to_string(),
        );
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
            process_packets(
                &mut thread_lb,
                incoming_rx,
                outgoing_tx,
                stats_tx,
                &mut arp_cache,
            );
        });

        let client_ip: Ipv4Addr = "9.9.9.9".parse().unwrap();
        let backend_srv_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();

        {
            // set a backend server to healthy
            let mut srvs_map = lb.backend.servers_map.write().unwrap();
            let mut srvs_ring = lb.backend.ring.lock().unwrap();
            let health = srvs_map
                .get_mut(&SocketAddr::new(IpAddr::V4(backend_srv_ip), 3080))
                .unwrap();
            *health = true;
            srvs_ring.add_node(&Node {
                host: IpAddr::V4(backend_srv_ip),
                port: 3080,
            })
        }

        // simulated client packet
        let test_eth = build_dummy_eth(client_ip, lb_ip, 35000, 3000);
        // send to process packet thread
        incoming_tx
            .send(EthernetPacket::owned(test_eth.packet().to_owned()).unwrap())
            .unwrap();

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
        incoming_tx
            .send(EthernetPacket::owned(test_eth.packet().to_owned()).unwrap())
            .unwrap();
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
            process_packets(
                &mut thread_lb,
                incoming_rx,
                outgoing_tx,
                stats_tx,
                &mut arp_cache,
            );
        });

        let client_ip: Ipv4Addr = "9.9.9.9".parse().unwrap();
        let backend_srv_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();

        {
            // set a backend server to healthy
            let mut srvs_map = lb.backend.servers_map.write().unwrap();
            let mut srvs_ring = lb.backend.ring.lock().unwrap();
            let health = srvs_map
                .get_mut(&SocketAddr::new(IpAddr::V4(backend_srv_ip), 3080))
                .unwrap();
            *health = true;
            srvs_ring.add_node(&Node {
                host: IpAddr::V4(backend_srv_ip),
                port: 3080,
            })
        }

        // simulated client packet
        let test_eth = build_dummy_eth(client_ip, lb_ip, 35000, 3000);
        // send to process packet thread
        incoming_tx
            .send(EthernetPacket::owned(test_eth.packet().to_owned()).unwrap())
            .unwrap();

        // read and verify the outgoing processed packet
        let fwd_pkt: MutableIpv4Packet = outgoing_rx.recv().unwrap();
        assert_eq!(fwd_pkt.get_destination(), backend_srv_ip);
        assert_eq!(fwd_pkt.get_source(), client_ip);

        let tcp_resp = TcpPacket::new(fwd_pkt.payload()).unwrap();
        assert_eq!(tcp_resp.get_destination(), 3080);
        assert_eq!(tcp_resp.get_source(), 35000);
    }
}
