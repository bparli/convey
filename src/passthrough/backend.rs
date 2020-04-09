extern crate futures;
extern crate hash_ring;

use self::passthrough::utils::allocate_socket;
use crate::passthrough;
use crate::stats::StatsMssg;
use hash_ring::HashRing;
use socket2::SockAddr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::time;

#[derive(Debug, Clone)]
pub struct Node {
    pub host: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct ServerPool {
    pub servers_map: HashMap<SocketAddr, bool>,

    pub ring: HashRing<Node>,
}

#[derive(Debug, Clone)]
pub struct Backend {
    pub name: String,

    pub health_check_interval: u64,

    pub servers_map: Arc<RwLock<HashMap<SocketAddr, bool>>>,

    pub ring: Arc<Mutex<HashRing<Node>>>,
}

impl ToString for Node {
    fn to_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Backend {
    pub fn new(
        name: String,
        servers: HashMap<SocketAddr, Option<u16>>,
        health_check_interval: u64,
    ) -> Backend {
        let pool = ServerPool::new_servers(servers);
        Backend {
            name: name,
            servers_map: Arc::new(RwLock::new(pool.servers_map)),
            ring: Arc::new(Mutex::new(pool.ring)),
            health_check_interval: health_check_interval,
        }
    }

    pub fn get_server(
        &self,
        ip_dst: IpAddr,
        port_dst: u16,
        ip_src: IpAddr,
        port_src: u16,
    ) -> Option<Node> {
        // Build "4-tuple" of destination ip, destination port, source ip, source port
        // in form of str to feed to hashring
        let mut tuple: String = ip_dst.to_string();
        tuple.push_str(&port_dst.to_string());
        tuple.push_str(&ip_src.to_string());
        tuple.push_str(&port_src.to_string());

        let mut srvs_ring = self.ring.lock().unwrap();
        debug!(
            "Scheduling backend server for {} with ring {:?}",
            tuple, srvs_ring
        );
        match srvs_ring.get_node(tuple.to_string().clone()) {
            Some(node) => {
                debug!("Scheduled backend server {:?} for tuple {}", node, tuple);
                Some(node.clone())
            }
            None => None,
        }
    }

    pub fn get_server_health(&self, server: Node) -> bool {
        match self
            .servers_map
            .read()
            .unwrap()
            .get(&SocketAddr::new(server.host, server.port))
        {
            Some(healthy) => *healthy,
            None => false,
        }
    }

    fn update_backends_health(&self, updates: &HashMap<SocketAddr, bool>) {
        let mut srvs_map = self.servers_map.write().unwrap();
        let mut srvs_ring = self.ring.lock().unwrap();
        for (srv, healthy) in updates {
            if let Some(s) = srvs_map.get_mut(&srv) {
                debug!("Set {} health status to {} from {}", srv, *healthy, *s);
                *s = *healthy;
                if *healthy {
                    srvs_ring.add_node(&Node {
                        host: srv.ip(),
                        port: srv.port(),
                    })
                } else {
                    srvs_ring.remove_node(&Node {
                        host: srv.ip(),
                        port: srv.port(),
                    })
                }
            }
        }
    }
}

impl ServerPool {
    pub fn new_servers(servers: HashMap<SocketAddr, Option<u16>>) -> ServerPool {
        let mut backend_servers = HashMap::new();
        let mut nodes: Vec<Node> = Vec::new();

        // this consistent hashing doesn't consider weights so disregard the weight field
        for (server, _) in &servers {
            // only support ipv4 for now
            if server.is_ipv4() {
                if simple_tcp_health_check(*server) {
                    backend_servers.insert(*server, true);
                    nodes.push(Node {
                        host: server.ip(),
                        port: server.port(),
                    })
                } else {
                    backend_servers.insert(*server, false);
                }
            } else {
                continue;
            }
        }

        debug!(
            "New Server Pool with map {:?} and hashring nodes {:?}",
            backend_servers, nodes
        );
        ServerPool {
            servers_map: backend_servers,
            ring: HashRing::new(nodes, 100),
        }
    }
}

fn simple_tcp_health_check(server: SocketAddr) -> bool {
    if let Ok(_) = TcpStream::connect_timeout(&server, time::Duration::from_secs(3)) {
        true
    } else {
        false
    }
}

// tcp_health_check is a more complex tcpstream with connection timeout and binding to a
// local port so as not to collide with load balanced packets
fn tcp_health_check(server: SocketAddr, ip: Ipv4Addr) -> bool {
    if let Some(sock) = allocate_socket(ip) {
        if let Ok(_) = sock.connect_timeout(&SockAddr::from(server), time::Duration::from_secs(3)) {
            return true;
        } else {
            return false;
        }
    }
    error!("Unable to allocate port for health checking");
    true
}

pub fn health_checker(backend: Arc<Backend>, sender: &Sender<StatsMssg>, local_ip: Ipv4Addr) {
    let mut backend_status = HashMap::new();
    let mut backend_updates = HashMap::new();
    // limit scope of read lock
    {
        for (server, status) in backend.servers_map.read().unwrap().iter() {
            let res = tcp_health_check(*server, local_ip);
            if res != *status {
                info!(
                    "Server {} status has changed from {} to {}.  Updating stats and backend",
                    server, status, res
                );
                backend_updates.insert(server.clone(), res);
            }
            backend_status.insert(server.clone(), res);
        }
    }

    // update_backends_health uses the write lock so only call it when absolutely necessary
    if backend_updates.len() > 0 {
        backend.update_backends_health(&backend_updates);
    }

    send_status(backend.name.clone(), backend_status, sender);
}

fn send_status(name: String, updates: HashMap<SocketAddr, bool>, sender: &Sender<StatsMssg>) {
    let mut servers = HashMap::new();
    for (srv, healthy) in updates {
        servers.insert(srv.to_string(), healthy);
    }
    let mssg = StatsMssg {
        frontend: None,
        backend: name.clone(),
        connections: 0,
        bytes_tx: 0,
        bytes_rx: 0,
        servers: Some(servers),
    };
    match sender.send(mssg) {
        Ok(_) => {}
        Err(e) => error!("Error sending stats message on channel: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::str::FromStr;
    use std::sync::mpsc::channel;
    use std::{thread, time};

    #[test]
    fn test_new_servers_pt() {
        thread::spawn(|| {
            let listener = TcpListener::bind("127.0.0.1:9070").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {}
                Err(_e) => {}
            }
        });

        let two_sec = time::Duration::from_secs(2);
        thread::sleep(two_sec);

        let mut test_servers = HashMap::new();
        test_servers.insert(FromStr::from_str("127.0.0.1:9070").unwrap(), None);
        test_servers.insert(FromStr::from_str("127.0.0.1:9071").unwrap(), Some(100));

        let mut test_pool = ServerPool::new_servers(test_servers);
        let test_srv = test_pool
            .servers_map
            .get(&FromStr::from_str("127.0.0.1:9071").unwrap())
            .unwrap();
        assert_eq!(*test_srv, false);

        // test scheduling from hashring
        let test_node = test_pool.ring.get_node("Dummy-tuple".to_string()).unwrap();
        assert_eq!(test_node.port, 9070);
    }

    #[test]
    fn test_backend_get_server_pt() {
        // setup iptables for passthrough mode (iptables -t raw -A PREROUTING -p tcp --dport 3000 -j DROP)

        thread::spawn(|| {
            let listener = TcpListener::bind("127.0.0.1:9090").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {}
                Err(_e) => {}
            }
        });

        let two_sec = time::Duration::from_secs(2);
        thread::sleep(two_sec);

        let mut test_servers = HashMap::new();
        test_servers.insert(FromStr::from_str("127.0.0.1:9090").unwrap(), None);
        test_servers.insert(FromStr::from_str("127.0.0.1:9091").unwrap(), Some(100));

        let test_bck = Backend::new("test".to_string(), test_servers, 1000);
        assert_eq!(test_bck.health_check_interval, 1000);
        assert_eq!(
            *test_bck
                .servers_map
                .read()
                .unwrap()
                .get(&SocketAddr::new("127.0.0.1".parse().unwrap(), 9090))
                .unwrap(),
            true
        );
        assert_eq!(
            *test_bck
                .servers_map
                .read()
                .unwrap()
                .get(&SocketAddr::new("127.0.0.1".parse().unwrap(), 9091))
                .unwrap(),
            false
        );
        assert_eq!(
            test_bck
                .get_server(
                    "127.0.0.1".parse().unwrap(),
                    32000,
                    "127.0.0.1".parse().unwrap(),
                    33000
                )
                .unwrap()
                .port,
            9090
        );

        let mut test_updates = HashMap::new();
        test_updates.insert(FromStr::from_str("127.0.0.1:9090").unwrap(), false);
        test_updates.insert(FromStr::from_str("127.0.0.1:9091").unwrap(), true);
        test_bck.update_backends_health(&test_updates);

        assert_eq!(
            *test_bck
                .servers_map
                .read()
                .unwrap()
                .get(&SocketAddr::new("127.0.0.1".parse().unwrap(), 9091))
                .unwrap(),
            true
        );
        assert_eq!(
            test_bck
                .get_server(
                    "127.0.0.1".parse().unwrap(),
                    32000,
                    "127.0.0.1".parse().unwrap(),
                    33000
                )
                .unwrap()
                .port,
            9091
        );

        let mut test_updates = HashMap::new();
        test_updates.insert(FromStr::from_str("127.0.0.1:9090").unwrap(), false);
        test_updates.insert(FromStr::from_str("127.0.0.1:9091").unwrap(), false);
        test_bck.update_backends_health(&test_updates);
        match test_bck.get_server(
            "127.0.0.1".parse().unwrap(),
            32000,
            "127.0.0.1".parse().unwrap(),
            33000,
        ) {
            Some(_) => assert!(false),
            None => assert!(true),
        }

        // Flush iptables
    }

    #[test]
    fn test_health_checker_pt() {
        let mut test_servers = HashMap::new();
        let test_addr = FromStr::from_str("127.0.0.1:9089").unwrap();
        test_servers.insert(test_addr, None);

        // nothing listening on 127.0.0.1:8080 yet so should be marked as unhealthy
        let test_bck = Arc::new(Backend::new("dummy".to_string(), test_servers, 1000));
        {
            assert_eq!(
                *test_bck
                    .servers_map
                    .read()
                    .unwrap()
                    .get(&test_addr)
                    .unwrap(),
                false
            );
        }

        // start listening on 127.0.0.1:8089 so next health checks will mark as healthy
        thread::spawn(|| {
            let listener = TcpListener::bind("127.0.0.1:9089").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {}
                Err(_e) => {}
            }
        });
        let one_sec = time::Duration::from_secs(1);
        thread::sleep(one_sec);

        let (tx, rx) = channel();

        // run health chcker
        health_checker(test_bck.clone(), &tx, "127.0.0.1".parse().unwrap());

        // verify repsonse message
        let resp = rx.recv().unwrap();
        assert_eq!(resp.backend, "dummy".to_string());
        match resp.servers {
            Some(srvs) => {
                assert!(srvs.get("127.0.0.1:9089").unwrap());
            }
            None => assert!(false),
        }
    }
}
