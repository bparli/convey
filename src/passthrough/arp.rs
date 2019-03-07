extern crate pnet;

use std::collections::BTreeMap;
use std::net::{Ipv4Addr};
use pnet::util::MacAddr;
use pnet::datalink::{NetworkInterface};
use ipnetwork::{IpNetwork, Ipv4Network};
use pnet::packet::arp::{ ArpOperations, ArpPacket};

use pnet::packet::{Packet};
use pnet::packet::ethernet::{EthernetPacket};
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
    cache: BTreeMap<Ipv4Addr, MacAddr>,
}

impl Arp {
    pub fn new(interface: NetworkInterface, addr: Ipv4Addr) -> Option<Arp> {
        let mut local_net = interface.ips[0];
        for ip in interface.ips {
            if ip.ip() == addr {
                local_net = ip;
                break
            }
        }

        if let IpNetwork::V4(ipv4_net) = local_net {
            let tb = Table{
                default_gw_mac: None,
                cache: BTreeMap::new(),
            };
            return Some(Arp {
                    local: interface.mac.unwrap(),
                    network: ipv4_net,
                    // assume the default gateway is the network address + 1
                    default_gw: ipv4_net.nth(1).unwrap(),
                    table: Arc::new(RwLock::new(tb)),
            })
        }
        error!("Unable to build Arp structure due to supplied interface and network (should be ipv4)");
        None
    }

    pub fn handle_arp(&mut self, ethernet: &EthernetPacket) {
        let header = ArpPacket::new(ethernet.payload());
        if let Some(header) = header {
            if header.get_operation() == ArpOperations::Reply {
                if self.network.contains(header.get_sender_proto_addr()) {
                    let mut update = false;
                    {
                        if !self.table.read().unwrap().cache.contains_key(&header.get_sender_proto_addr()) {
                            update = true
                        }
                    }
                    if update {
                        let mut tb = self.table.write().unwrap();
                        tb.cache.insert(header.get_sender_proto_addr(), header.get_sender_hw_addr());
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
        return self.table.read().unwrap().default_gw_mac
    }

    pub fn get_mac(&mut self, ip: Ipv4Addr) -> Option<MacAddr> {
        if let Some(mac) = self.table.read().unwrap().cache.get(&ip) {
            return Some(mac.clone())
        } else {
            None
        }
    }
}
