extern crate crossbeam_channel;
extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::datalink::{linux, DataLinkReceiver, DataLinkSender};
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
//use std::sync::mpsc::{channel, Receiver, Sender};

use crossbeam_channel::{bounded, Receiver, Sender};

#[derive(Clone)]
pub struct Arp {
    pub local_mac: MacAddr,
    network: Ipv4Network,
    pub default_gw: Ipv4Addr,
    table: Arc<RwLock<Table>>,
    broadcast_tx: Sender<Ipv4Addr>,
}

struct Table {
    default_gw_mac: Option<MacAddr>,
    cache: HashMap<Ipv4Addr, MacAddr>,
}

impl Arp {
    pub fn new(interface: NetworkInterface, addr: Ipv4Addr) -> Option<Arp> {
        let mut local_net = interface.ips[0];
        for ip in &interface.ips {
            if ip.ip() == addr {
                local_net = *ip;
                break;
            }
        }

        // Create a new channel, dealing with layer 2 packets
        let (iface_tx, iface_rx) = match linux::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };

        if let IpNetwork::V4(ipv4_net) = local_net {
            let tb = Table {
                default_gw_mac: None,
                cache: HashMap::new(),
            };

            let (l2_broadcast_tx, l2_broadcast_rx) = bounded(1024);

            let arp_cache = Arp {
                local_mac: interface.mac.unwrap(),
                network: ipv4_net,
                // assume the default gateway is the network address + 1
                default_gw: ipv4_net.nth(1).unwrap(),
                table: Arc::new(RwLock::new(tb)),
                broadcast_tx: l2_broadcast_tx.clone(),
            };

            // first start listener
            arp_cache.clone().l2_listen(iface_rx);

            // also start broadcast thread
            l2_broadcast_arp(iface_tx, l2_broadcast_rx, interface.mac.unwrap(), addr);

            // now our arp cache is ready
            return Some(arp_cache);
        }
        error!(
            "Unable to build Arp structure due to supplied interface and network (should be ipv4)"
        );
        None
    }

    pub fn start(self) {
        // now send arp requests for default GW
        self.clone().boot_arp_table();
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

    pub fn get_default_mac(&mut self) -> Option<MacAddr> {
        return self.table.read().unwrap().default_gw_mac;
    }

    // if ip is in local network return its mac address, else send to default GW
    pub fn get_mac(&mut self, ip: Ipv4Addr) -> Option<MacAddr> {
        if self.network.contains(ip) {
            if let Some(mac) = self.table.read().unwrap().cache.get(&ip) {
                return Some(mac.clone());
            }
            // missing ip in our arp cache, send out an Arp request
            debug!("Missing address in arp cache, sending arp request");
            match self.broadcast_tx.send(ip) {
                Ok(_) => {}
                Err(e) => {
                    error!("Unable to send Arp request for IP {}: {}", ip, e);
                }
            }
        }
        self.get_default_mac()
    }

    // blocks until we've gotten the default gateway HW address
    fn boot_arp_table(mut self) {
        loop {
            match self.broadcast_tx.send(self.default_gw) {
                Ok(_) => {}
                Err(e) => {
                    error!("Unable to send Arp request for Default GW: {}", e);
                }
            }
            // loop until we've received the arp response from the default gateway
            thread::sleep(Duration::from_millis(200));
            if let Some(_mac) = self.get_default_mac() {
                break;
            }
            debug!("Sending another ARP request for Default Gateway's HW Addr");
        }
    }

    // background thread to snoop on ARPs so we can fill out our table
    fn l2_listen(mut self, mut iface_rx: Box<dyn DataLinkReceiver>) {
        thread::spawn(move || loop {
            match iface_rx.next() {
                Ok(packet) => {
                    let ethernet = EthernetPacket::owned(packet.to_vec()).unwrap();
                    match ethernet.get_ethertype() {
                        EtherTypes::Arp => self.handle_arp(&ethernet),
                        _ => {}
                    }
                }
                Err(e) => {
                    error!("An error occurred while reading: {}", e);
                }
            }
        });
    }
}

pub fn get_broadcast_addr() -> MacAddr {
    MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
}

// listen on a channel for IPs to send ARP requests for
fn l2_broadcast_arp(
    mut iface_tx: Box<dyn DataLinkSender>,
    rx: Receiver<Ipv4Addr>,
    mac_addr: MacAddr,
    local_ip: Ipv4Addr,
) {
    thread::spawn(move || loop {
        match rx.recv() {
            Ok(ipv4_addr) => {
                iface_tx.build_and_send(1, 42, &mut |eth_packet| {
                    let mut eth_packet = MutableEthernetPacket::new(eth_packet).unwrap();

                    eth_packet.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
                    eth_packet.set_source(mac_addr);
                    eth_packet.set_ethertype(EtherTypes::Arp);

                    let mut arp_buffer = [0u8; 28];
                    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

                    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                    arp_packet.set_protocol_type(EtherTypes::Ipv4);
                    arp_packet.set_hw_addr_len(6);
                    arp_packet.set_proto_addr_len(4);
                    arp_packet.set_operation(ArpOperations::Request);
                    arp_packet.set_sender_hw_addr(mac_addr);
                    arp_packet.set_sender_proto_addr(local_ip);
                    arp_packet.set_target_hw_addr(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
                    arp_packet.set_target_proto_addr(ipv4_addr);

                    eth_packet.set_payload(arp_packet.packet());
                });
            }
            Err(e) => {
                error!("Error reading ipv4 address for L2 broadcast: {}", e);
            }
        }
    });
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
    use std::net::Ipv4Addr;

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
            let interface = find_interface(local_ip).unwrap();
            let mut test_arp = passthrough::arp::Arp::new(interface, local_ip).unwrap();

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
            arp_packet.set_sender_proto_addr(local_ip);
            arp_packet.set_target_hw_addr(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
            arp_packet.set_target_proto_addr(local_ip);

            eth_header.set_payload(arp_packet.packet());

            test_arp.handle_arp(&eth_header.to_immutable());

            assert_eq!(
                test_arp.get_mac(local_ip).unwrap(),
                MacAddr::new(255, 255, 255, 255, 255, 255)
            )
        } else {
            assert!(false)
        }
    }
}
