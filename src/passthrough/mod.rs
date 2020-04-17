extern crate lru_time_cache;
extern crate pnet;
extern crate pnet_macros_support;

use self::backend::{health_checker, ServerPool};
use self::lb::LB;
use self::utils::find_interface;

use crate::config::{BaseConfig, Config};
use crate::stats::StatsMssg;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{linux, FanoutOption, FanoutType, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::Packet;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer3;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

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
    interface: NetworkInterface,
    interface_cfg: linux::Config,
    stats_sender: Sender<StatsMssg>,
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

    // Create a new channel, dealing with layer 2 packets
    let (_, mut iface_rx) = match linux::channel(&interface, interface_cfg) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    let protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (mut ipv4_tx, _) = transport_channel(4096, protocol).unwrap();

    loop {
        match iface_rx.next() {
            Ok(frame) => {
                let ethernet = EthernetPacket::new(frame).unwrap();
                match ethernet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        match MutableIpv4Packet::owned(ethernet.payload().to_owned()) {
                            Some(mut ip_header) => {
                                let dst = ip_header.get_destination();
                                if dst == lb.listen_ip {
                                    match MutableTcpPacket::owned(ip_header.payload().to_owned()) {
                                        Some(mut tcp_header) => {
                                            if tcp_header.get_destination() == lb.listen_port {
                                                if let Some(processed_packet) = lb.client_handler(
                                                    &mut ip_header,
                                                    &mut tcp_header,
                                                    &mut ipv4_tx,
                                                ) {
                                                    stats.connections +=
                                                        &processed_packet.pkt_stats.connections;
                                                    stats.bytes_rx +=
                                                        &processed_packet.pkt_stats.bytes_rx;
                                                    stats.bytes_tx +=
                                                        &processed_packet.pkt_stats.bytes_tx;
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
                                                        if let Some(processed_packet) = lb
                                                            .server_response_handler(
                                                                &mut ip_header,
                                                                &mut tcp_header,
                                                                cli_socket,
                                                                &mut ipv4_tx,
                                                            )
                                                        {
                                                            stats.connections += &processed_packet
                                                                .pkt_stats
                                                                .connections;
                                                            stats.bytes_rx += &processed_packet
                                                                .pkt_stats
                                                                .bytes_rx;
                                                            stats.bytes_tx += &processed_packet
                                                                .pkt_stats
                                                                .bytes_tx;
                                                        };
                                                    }
                                                    None => {}
                                                }
                                            }
                                            match stats_rx.try_recv() {
                                                Ok(_) => {
                                                    // send the counters we've gathered in this time period
                                                    debug!("Timer fired, sending stats counters");
                                                    match stats_sender.send(stats.clone()) {
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

    // find local interface we should be listening and sending on
    // to setup this datalink channel we can't be on a loopback
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

    let cfg = setup_interface_cfg();
    // spawn the packet processing workers
    for _ in 0..lb.workers {
        let mut thread_lb = lb.clone();
        let iface = interface.clone();
        let thread_sender = sender.clone();
        thread::spawn(move || process_packets(&mut thread_lb, iface, cfg, thread_sender));
    }

    // start health checks in main thread
    loop {
        health_checker(lb.backend.clone(), &sender, lb.listen_ip);
        let interval = Duration::from_secs(lb.backend.health_check_interval);
        thread::sleep(interval);
    }
}

fn setup_interface_cfg() -> linux::Config {
    let fanout = Some(FanoutOption {
        group_id: rand::random::<u16>(),
        fanout_type: FanoutType::LB,
        defrag: true,
        rollover: false,
    });
    linux::Config {
        fanout: fanout,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    extern crate hyper;
    use self::passthrough::backend::Node;
    use self::passthrough::process_packets;
    use self::passthrough::utils::{find_interface, find_local_addr, build_dummy_ip, EPHEMERAL_PORT_LOWER};
    use crate::config::Config;
    use crate::passthrough;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
    use pnet::packet::Packet;
    use pnet::transport::{ipv4_packet_iter, transport_channel};
    use pnet::transport::TransportChannelType::Layer3;
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

        let dummy_ip = "127.0.0.1".parse().unwrap();

        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (mut ipv4_tx, _) = transport_channel(4096, protocol).unwrap();

        for i in 0..5 {
            let mut ip_header = build_dummy_ip(dummy_ip, dummy_ip, 35000 + i, 3000);
            let mut tcp_header = MutableTcpPacket::owned(ip_header.payload().to_owned()).unwrap();
            lb.client_handler(&mut ip_header, &mut tcp_header, &mut ipv4_tx);
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
        let mut lb = srv.lbs[0].clone();

        let local_addr = find_local_addr().unwrap();
        lb.listen_ip = local_addr;

        let (stats_tx, _) = channel();
        let mut thread_lb = lb.clone();
        let cfg = self::passthrough::setup_interface_cfg();
        let interface = find_interface(local_addr).unwrap();
        let iface = interface.clone();
        thread::spawn(move || {
            process_packets(
                &mut thread_lb,
                iface,
                cfg,
                stats_tx,
            );
        });

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

        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (mut ipv4_tx, mut ipv4_rx) = transport_channel(4096, protocol).unwrap();

        let client_ip: Ipv4Addr = "9.9.9.9".parse().unwrap();
        let ip_header = build_dummy_ip(client_ip, local_addr, 35000, 3000);
        ipv4_tx.send_to(ip_header, IpAddr::V4(local_addr)).unwrap();

        let mut iter = ipv4_packet_iter(&mut ipv4_rx);

        // listen for outgoing packet to backend sever
        loop {
            let (resp, _) = iter.next().unwrap();
            if resp.get_source() == local_addr {
                let tcp_resp = TcpPacket::new(resp.payload()).unwrap();
                if tcp_resp.get_source() == EPHEMERAL_PORT_LOWER {
                    assert_eq!(tcp_resp.get_destination(), 3080);
                }
                break;
            }
        }

        // simulate server response
        let server_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let ip_header = build_dummy_ip(server_ip, local_addr, 3080, EPHEMERAL_PORT_LOWER);
        ipv4_tx.send_to(ip_header, IpAddr::V4(local_addr)).unwrap();

        // listen for outgoing packet back to client
        loop {
            let (resp, _) = iter.next().unwrap();
            if resp.get_source() == server_ip {
                let tcp_resp = TcpPacket::new(resp.payload()).unwrap();
                if tcp_resp.get_source() == 3080 {
                    assert_eq!(tcp_resp.get_destination(), EPHEMERAL_PORT_LOWER);
                }
                break;
            }
        }
    }
}
