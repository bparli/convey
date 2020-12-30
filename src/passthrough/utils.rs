extern crate pnet;

use pnet::datalink::{linux, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::{tcp, Packet};
use socket2::{Domain, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// health ports are reserved for health checks
pub const HEALTH_PORT_LOWER: u16 = 32768;
pub const HEALTH_PORT_UPPER: u16 = 33767;
pub const EPHEMERAL_PORT_LOWER: u16 = 33768;
pub const EPHEMERAL_PORT_UPPER: u16 = 61000;

pub const ETHERNET_HEADER_LEN: usize = 14;
pub const IPV4_HEADER_LEN: usize = 20;
pub const TCP_HEADER_LEN: usize = 32;

pub fn find_local_addr() -> Option<Ipv4Addr> {
    for iface in pnet::datalink::interfaces() {
        for ipnet in iface.ips {
            if ipnet.is_ipv4() {
                match ipnet.ip() {
                    IpAddr::V4(ip) => return Some(ip),
                    _ => continue,
                }
            }
        }
    }
    None
}

// only use in tests!
pub fn build_dummy_ip(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> MutableIpv4Packet<'static> {
    // Setup TCP header
    let mut vec: Vec<u8> = vec![0; TCP_HEADER_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut vec[..]).unwrap();

    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);

    tcp_header.set_flags(tcp::TcpFlags::SYN);
    tcp_header.set_window(64240);
    tcp_header.set_data_offset(8);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_sequence(rand::random::<u32>());

    let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
    tcp_header.set_checksum(checksum);

    // Setup IP header
    let ipbuf: Vec<u8> = vec![0; TCP_HEADER_LEN + IPV4_HEADER_LEN];
    let mut ip_header = MutableIpv4Packet::owned(ipbuf).unwrap();
    ip_header.set_header_length(69);
    ip_header.set_total_length(52);
    ip_header.set_fragment_offset(16384);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ip);
    ip_header.set_destination(dst_ip);
    ip_header.set_identification(rand::random::<u16>());
    ip_header.set_ttl(128);
    ip_header.set_version(4);
    ip_header.set_payload(&tcp_header.packet());

    let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(checksum);

    ip_header
}

// only use in tests!
pub fn build_dummy_eth(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> MutableEthernetPacket<'static> {
    let ip_header = build_dummy_ip(src_ip, dst_ip, src_port, dst_port);

    // Setup Ethernet header
    let ethbuf: Vec<u8> = vec![0; TCP_HEADER_LEN + IPV4_HEADER_LEN + ETHERNET_HEADER_LEN];
    let mut eth_header = MutableEthernetPacket::owned(ethbuf).unwrap();

    eth_header.set_destination(MacAddr::new(255, 255, 255, 255, 255, 255));
    eth_header.set_source(MacAddr::new(255, 255, 255, 255, 255, 255));
    eth_header.set_ethertype(EtherTypes::Ipv4);
    eth_header.set_payload(&ip_header.packet());

    eth_header
}

// only use for health checks
pub fn allocate_socket(listen_ip: Ipv4Addr) -> Option<Socket> {
    // bind to a pre-determined local port and use a connection timeout
    let socket = Socket::new(Domain::ipv4(), Type::stream(), None).unwrap();
    for i in HEALTH_PORT_LOWER..HEALTH_PORT_UPPER {
        match socket.bind(&SockAddr::from(SocketAddr::new(IpAddr::V4(listen_ip), i))) {
            Ok(_) => return Some(socket),
            Err(_) => {}
        }
    }
    error!(
        "Unable to allocate local port from range {} - {}",
        HEALTH_PORT_LOWER, HEALTH_PORT_UPPER
    );
    None
}

pub fn find_interface(addr: Ipv4Addr) -> Option<NetworkInterface> {
    let interfaces = linux::interfaces();
    for interface in interfaces {
        for ip in interface.clone().ips {
            if ip.ip() == addr {
                return Some(interface);
            }
        }
    }
    None
}
