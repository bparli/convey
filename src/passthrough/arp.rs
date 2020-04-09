extern crate pnet;

use ipnetwork::{IpNetwork, Ipv4Network};
use pnet::datalink::NetworkInterface;
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct Arp {
    pub local: MacAddr,
    network: Ipv4Network,
    pub default_gw: Ipv4Addr,
    table: Arc<RwLock<Table>>,
}

struct Table {
    default_gw_mac: Option<MacAddr>,
    cache: HashMap<Ipv4Addr, MacAddr>,
}

impl Arp {
    pub fn new(interface: NetworkInterface, addr: Ipv4Addr) -> Option<Arp> {
        let mut local_net = interface.ips[0];
        for ip in interface.ips {
            if ip.ip() == addr {
                local_net = ip;
                break;
            }
        }

        if let IpNetwork::V4(ipv4_net) = local_net {
            let tb = Table {
                default_gw_mac: None,
                cache: HashMap::new(),
            };
            return Some(Arp {
                local: interface.mac.unwrap(),
                network: ipv4_net,
                // assume the default gateway is the network address + 1
                default_gw: ipv4_net.nth(1).unwrap(),
                table: Arc::new(RwLock::new(tb)),
            });
        }
        error!(
            "Unable to build Arp structure due to supplied interface and network (should be ipv4)"
        );
        None
    }

    pub fn handle_arp(&mut self, ethernet: &EthernetPacket) {
        let header = ArpPacket::new(ethernet.payload());
        if let Some(header) = header {
            if header.get_operation() == ArpOperations::Reply {
                if self.network.contains(header.get_sender_proto_addr()) {
                    let mut update = false;
                    {
                        if !self
                            .table
                            .read()
                            .unwrap()
                            .cache
                            .contains_key(&header.get_sender_proto_addr())
                        {
                            update = true
                        }
                    }
                    if update {
                        let mut tb = self.table.write().unwrap();
                        tb.cache
                            .insert(header.get_sender_proto_addr(), header.get_sender_hw_addr());
                        if header.get_sender_proto_addr() == self.default_gw {
                            debug!("Setting default gateway HW Address");
                            tb.default_gw_mac = Some(header.get_sender_hw_addr());
                        }
                    }
                }
            }
        } else {
            error!("Malformed ARP Packet: {:?}", header);
        }
    }

    pub fn get_default_mac(self) -> Option<MacAddr> {
        return self.table.read().unwrap().default_gw_mac;
    }

    pub fn get_mac(&mut self, ip: Ipv4Addr) -> Option<MacAddr> {
        if let Some(mac) = self.table.read().unwrap().cache.get(&ip) {
            return Some(mac.clone());
        } else {
            None
        }
    }
}
#[cfg(test)]
mod tests {
    use self::passthrough::find_interface;
    use self::passthrough::utils::find_local_addr;
    use crate::passthrough;
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::packet::Packet;
    use pnet::util::MacAddr;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_new_arp() {
        let ip4: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let interface = find_interface(ip4).unwrap();
        let test_arp = passthrough::arp::Arp::new(interface, ip4).unwrap();
        assert_eq!(test_arp.network.nth(1).unwrap(), ip4);
    }

    #[test]
    fn test_handle_arp() {
        if let Some(local_ip) = find_local_addr() {
            match local_ip {
                IpAddr::V4(ip4) => {
                    let interface = find_interface(ip4).unwrap();
                    let mut test_arp = passthrough::arp::Arp::new(interface, ip4).unwrap();

                    // Setup Ethernet header
                    let ethbuf: Vec<u8> = vec![0; 42];
                    let mut eth_header = MutableEthernetPacket::owned(ethbuf).unwrap();

                    eth_header.set_destination(MacAddr::new(255, 255, 255, 255, 255, 255));
                    eth_header.set_source(MacAddr::new(255, 255, 255, 255, 255, 255));
                    eth_header.set_ethertype(EtherTypes::Arp);

                    let mut arp_buffer = [0u8; 28];
                    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

                    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                    arp_packet.set_protocol_type(EtherTypes::Ipv4);
                    arp_packet.set_hw_addr_len(6);
                    arp_packet.set_proto_addr_len(4);
                    arp_packet.set_operation(ArpOperations::Reply);
                    arp_packet.set_sender_hw_addr(MacAddr::new(255, 255, 255, 255, 255, 255));
                    arp_packet.set_sender_proto_addr(ip4);
                    arp_packet.set_target_hw_addr(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
                    arp_packet.set_target_proto_addr(ip4);

                    eth_header.set_payload(arp_packet.packet());

                    test_arp.handle_arp(&eth_header.to_immutable());

                    assert_eq!(
                        test_arp.get_mac(ip4).unwrap(),
                        MacAddr::new(255, 255, 255, 255, 255, 255)
                    );
                }
                _ => assert!(false),
            }
        } else {
            assert!(false)
        }
    }
}
