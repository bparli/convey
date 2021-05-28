extern crate pnet;

use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use pnet::util::MacAddr;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use super::{fetch_arp_table, get_default_gw};

const ARP_INTERVAL: u64 = 5;

#[derive(Clone)]
pub struct Arp {
    pub local_mac: MacAddr,
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
        for ip in &interface.ips {
            if ip.ip() == addr {
                local_net = *ip;
                break;
            }
        }

        if let IpNetwork::V4(ipv4_net) = local_net {
            let mut tb = Table {
                default_gw_mac: None,
                cache: HashMap::new(),
            };

            // first grab the default GW IP Addr
            let default_gw: Ipv4Addr;
            loop {
                match get_default_gw(interface.name.clone()) {
                    Ok(addr) => {
                        default_gw = addr;
                        break;
                    }
                    Err(e) => {
                        error!("Retrying default gateway: {}", e);
                    }
                }
            }

            loop {
                // ensure we load up the addresses from the OS
                if let Ok(arps) = fetch_arp_table() {
                    tb.cache = arps;
                    if let Some(mac) = tb.cache.get(&default_gw) {
                        tb.default_gw_mac = Some(*mac);
                        break;
                    } else {
                        error!("Unable to learn default GW Mac Address, retrying");
                    }
                } else {
                    error!("Unable to load Arp Table, retrying");
                }
            }

            let arp_cache = Arp {
                local_mac: interface.mac.unwrap(),
                network: ipv4_net,
                // assume the default gateway is the network address + 1
                default_gw,
                table: Arc::new(RwLock::new(tb)),
            };

            // finally, now our arp cache is ready
            return Some(arp_cache);
        }
        error!(
            "Unable to build Arp structure due to supplied interface and network (should be ipv4)"
        );
        None
    }

    pub fn start(self) {
        // background thread to periodically reload the arp table addresses
        thread::spawn(move || loop {
            if let Ok(arps) = fetch_arp_table() {
                let mut tb = self.table.write().unwrap();
                tb.cache = arps;
            }
            thread::sleep(Duration::from_secs(ARP_INTERVAL));
        });
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
            debug!("Missing address in arp cache");
        }
        None
    }

    pub fn get_network(&self) -> Ipv4Network {
        return self.network;
    }
}

pub fn get_broadcast_addr() -> MacAddr {
    MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
}

#[cfg(test)]
mod tests {
    use self::passthrough::find_interface;
    use crate::passthrough;
    use std::net::Ipv4Addr;

    #[test]
    fn test_new_arp() {
        let ip4: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let interface = find_interface(ip4).unwrap();
        let test_arp = passthrough::arp::Arp::new(interface, ip4).unwrap();
        assert_eq!(test_arp.network.nth(1).unwrap(), ip4);
    }
}
