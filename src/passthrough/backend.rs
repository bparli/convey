extern crate futures;
extern crate hash_ring;

use std::net::SocketAddr;
use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::{Arc, RwLock};
use crate::stats::StatsMssg;
use std::sync::mpsc::{Sender};
use std::net::{IpAddr};
use hash_ring::HashRing;

#[derive(Debug, Clone)]
pub struct Node {
    pub host: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct ServerPool {
    pub servers_map: HashMap<SocketAddr, bool>,

    ring: HashRing<Node>,
}

#[derive(Debug, Clone)]
pub struct Backend {
    pub name: String,
    pub servers: Arc<RwLock<ServerPool>>,
    pub health_check_interval: u64,
}

impl ToString for Node {
    fn to_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Backend {
    pub fn new(name: String, servers: HashMap<SocketAddr, Option<u16>>, health_check_interval: u64) -> Backend {
        let backend_servers = ServerPool::new_servers(servers);
        Backend {
            name: name,
            servers: Arc::new(RwLock::new(backend_servers)),
            health_check_interval: health_check_interval,
        }
    }

    pub fn get_server(&self, ip_dst: IpAddr, port_dst: u16, ip_src: IpAddr, port_src: u16) -> Option<Node> {

        // Build "4-tuple of destination ip, destination port, source ip, source port
        // in form of str to feed to hashring"
        let mut tuple: String = ip_dst.to_string();
        tuple.push_str(&port_dst.to_string());
        tuple.push_str(&ip_src.to_string());
        tuple.push_str(&port_src.to_string());

        let srvs = self.servers.read().unwrap();
        let mut new_ring = srvs.ring.clone();

        match new_ring.get_node(tuple.to_string().clone()){
            Some(node) => Some(node.clone()),
            None => None,
        }
    }

    fn update_backends_health(&self, updates: &HashMap<SocketAddr, bool>) {
        let mut srvs = self.servers.write().unwrap();
        for (srv, healthy) in updates {
            if let Some(s) = srvs.servers_map.get_mut(&srv) {
                debug!("Set {} health status to {} from {}", srv, *healthy, *s);
                *s = *healthy;
                if *healthy {
                    srvs.ring.add_node(&Node{host: srv.ip(), port: srv.port()})
                } else {
                    srvs.ring.remove_node(&Node{host: srv.ip(), port: srv.port()})
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
                if tcp_health_check(*server) {
                    backend_servers.insert(*server, true);
                    nodes.push(Node{host: server.ip().clone(), port: server.port()})
                } else {
                    backend_servers.insert(*server, false);
                }
            } else {
                continue
            }
        }

        debug!("New Server Pool with map {:?} and hashring nodes {:?}", backend_servers, nodes);
        ServerPool{
            servers_map: backend_servers,
            ring: HashRing::new(nodes, 100),
        }
    }
}

fn tcp_health_check(server: SocketAddr) -> bool {
    if let Ok(_) = TcpStream::connect(server) {
        true
    } else {
        false
    }
}

pub fn health_checker(backend: Arc<Backend>, sender: &Sender<StatsMssg>) {
    let mut backend_status = HashMap::new();
    let mut update = false;
    // limit scope of read lock
    {
        let srvs = backend.servers.read().unwrap();
        for (server, status) in srvs.servers_map.iter() {
            let res = tcp_health_check(*server);
            if res != *status {
                info!("Server {} status has changed from {} to {}.  Updating stats and backend", server, status, res);
                update = true;
            }
            backend_status.insert(server.clone(), res);
        }
    }

    // update_backends_health uses the write lock so only call it when absolutely necessary
    if update {
        backend.update_backends_health(&backend_status);
    }

    send_status(backend.name.clone(), backend_status, sender);
}

fn send_status(name: String, updates: HashMap<SocketAddr, bool>, sender: &Sender<StatsMssg>) {
    let mut servers = HashMap::new();
    for (srv, healthy) in updates {
        servers.insert(srv.to_string(), healthy);
    }
    let mssg = StatsMssg{frontend: None,
                        backend: name.clone(),
                        connections: 0,
                        bytes_tx: 0,
                        bytes_rx: 0,
                        servers: Some(servers)};
    match sender.send(mssg) {
        Ok(_) => {},
        Err(e) => error!("Error sending stats message on channel: {}", e)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use std::str::FromStr;
    use std::net::TcpListener;
    use std::{thread, time};

    #[test]
    fn test_new_servers() {
        thread::spawn( ||{
            let listener = TcpListener::bind("127.0.0.1:8070").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {},
                Err(_e) => {},
            }
        });

        let one_sec = time::Duration::from_secs(1);
        thread::sleep(one_sec);

        let mut test_servers = HashMap::new();
        test_servers.insert(FromStr::from_str("127.0.0.1:8070").unwrap(), None);
        test_servers.insert(FromStr::from_str("127.0.0.1:8071").unwrap(), Some(100));

        let test_pool = ServerPool::new_servers(test_servers);


    }

    #[test]
    fn test_backend() {
        thread::spawn( ||{
            let listener = TcpListener::bind("127.0.0.1:8090").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {},
                Err(_e) => {},
            }
        });

        let one_sec = time::Duration::from_secs(1);
        thread::sleep(one_sec);

        let mut test_servers = HashMap::new();
        test_servers.insert(FromStr::from_str("127.0.0.1:8090").unwrap(), None);
        test_servers.insert(FromStr::from_str("127.0.0.1:8091").unwrap(), Some(100));

        let test_bck = Backend::new("test".to_string(), test_servers, 1000);
        assert_eq!(test_bck.health_check_interval, 1000);

        let mut test_updates = HashMap::new();
        test_updates.insert(FromStr::from_str("127.0.0.1:8091").unwrap(), true);
        test_bck.update_backends_health(&test_updates);

        let test_pool = test_bck.servers.read().unwrap();
    }

    #[test]
    fn test_get_server() {
        thread::spawn( ||{
            let listener = TcpListener::bind("127.0.0.1:8082").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {},
                Err(_e) => {},
            }
        });

        let one_sec = time::Duration::from_secs(1);
        thread::sleep(one_sec);

        let mut test_servers = HashMap::new();
        test_servers.insert(FromStr::from_str("127.0.0.1:8082").unwrap(), Some(20));
        let test_bck = Arc::new(Backend::new("test".to_string(), test_servers, 1000));


    }

    #[test]
    fn test_health_checker() {
        let mut test_servers = HashMap::new();
        let test_addr = FromStr::from_str("127.0.0.1:8089").unwrap();
        test_servers.insert(test_addr, None);

        // nothing listening on 127.0.0.1:8080 yet so should be marked as unhealthy
        let test_bck = Arc::new(Backend::new("dummy".to_string(), test_servers, 1000));
        {
            let test_srv_pool = test_bck.servers.read().unwrap();
            assert_eq!(*test_srv_pool.servers_map.get(&test_addr).unwrap(), false);
        }

        // start listening on 127.0.0.1:8089 so next health checks will mark as healthy
        thread::spawn( ||{
            let listener = TcpListener::bind("127.0.0.1:8089").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {},
                Err(_e) => {},
            }
        });
        let one_sec = time::Duration::from_secs(1);
        thread::sleep(one_sec);

        let (tx, rx) = channel();

        // run health chcker
        health_checker(test_bck.clone(), &tx);

        // verify repsonse message
        let resp = rx.recv().unwrap();
        assert_eq!(resp.backend, "dummy".to_string());
        match resp.servers {
            Some(srvs) => {
                assert!(srvs.get("127.0.0.1:8089").unwrap());
            }
            None => assert!(false),
        }
    }
}
