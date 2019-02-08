extern crate futures;

use std::net::SocketAddr;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use futures::{Future, Async, Poll};
use std::net::TcpStream;
use std::sync::{Arc, RwLock};
use crate::stats::StatsMssg;
use std::sync::mpsc::{Sender};
use rand::distributions::WeightedIndex;
use rand::prelude::*;
use std::time;

#[derive(Debug, Clone)]
struct Wrr {
    healthy: bool,
    weight: u16,
    weights_index: usize,
}

#[derive(Debug, Clone)]
pub struct ServerPool {
    servers_map: HashMap<SocketAddr, Wrr>,
    weights: Vec<u16>,
    weighted_servers: Vec<SocketAddr>,
}

#[derive(Debug)]
pub struct Backend {
    pub name: String,
    pub servers: Arc<RwLock<ServerPool>>,
    pub health_check_interval: u64,
}

pub struct NextBackend {
    weighted_servers: Vec<SocketAddr>,
    weights: Vec<u16>,
}

impl ServerPool {
    pub fn new_servers(servers: HashMap<SocketAddr, Option<u16>>) -> ServerPool {
        let mut backend_servers = HashMap::new();
        let mut weighted_backend_servers = Vec::new();
        let mut weights = Vec::new();

        let mut index_count = 0;
        for (server, weight) in &servers {
            // set configured weight to 1 by default
            let mut server_weight: u16 = 1;
            match weight {
                Some(w) => server_weight = *w,
                None => {},
            }
            weighted_backend_servers.push(*server);
            if tcp_health_check(*server) {
                // server health check successful
                weights.push(server_weight);
                backend_servers.insert(*server, Wrr{healthy: true, weight: server_weight, weights_index: index_count});
            } else {
                // server health check not successful. set weight to 0
                weights.push(0);
                backend_servers.insert(*server, Wrr{healthy: false, weight: server_weight, weights_index: index_count});
            }

            index_count += 1;
        }
        debug!("Created weighted backend server pool: {:?}", backend_servers);

        let servers = ServerPool {
            servers_map: backend_servers,
            weights: weights,
            weighted_servers: weighted_backend_servers
        };
        servers
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

    fn update_backends_health(&self, updates: &HashMap<SocketAddr, bool>) {
        let mut srvs = self.servers.write().unwrap();
        let mut wgts = srvs.weights.clone();

        for (srv, healthy) in updates {
            if let Some(s) = srvs.servers_map.get_mut(&srv) {
                s.healthy = *healthy;
                if *healthy {
                    wgts[s.weights_index] = s.weight;
                } else {
                    wgts[s.weights_index] = 0;
                }
            }
        }
        srvs.weights = wgts;
    }
}

// custom future for backend server selection during load balancing
impl Future for NextBackend {
    type Item = SocketAddr;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Ok(dist) = WeightedIndex::new(&self.weights) {
            let mut rng = thread_rng();
            if let Some(target) = self.weighted_servers.get(dist.sample(&mut rng)) {
                return Ok(Async::Ready(*target));
            }
        }
        return Result::Err(Error::new(ErrorKind::Other, "No backend servers available"));
    }
}

pub fn get_next(backend: Arc<Backend>) -> NextBackend {
    let srvs = backend.servers.read().unwrap();

    NextBackend {
        weighted_servers: srvs.weighted_servers.clone(),
        weights: srvs.weights.clone(),
    }
}

fn tcp_health_check(server: SocketAddr) -> bool {
    if let Ok(_) = TcpStream::connect_timeout(&server, time::Duration::from_secs(3)) {
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
            if res != status.healthy {
                info!("Server {} status has changed from {} to {}.  Updating stats and backend", server, status.healthy, res);
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

        let mut test_weight: u16 = 0;
        assert!(test_pool.weights.contains(&test_weight));
        test_weight = 1;
        assert!(test_pool.weights.contains(&test_weight));
        assert_eq!(test_pool.weights.len(), 2);

        let test_srv = test_pool.servers_map.get(&FromStr::from_str("127.0.0.1:8071").unwrap()).unwrap();
        assert_eq!(test_srv.healthy, false);
        assert_eq!(test_srv.weight, 100);
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

        let mut test_weight: u16 = 100;
        assert!(test_pool.weights.contains(&test_weight));
        test_weight = 1;
        assert!(test_pool.weights.contains(&test_weight));
    }

    #[test]
    fn test_get_next() {
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

        let ftr = get_next(test_bck);
        let test_weight: u16 = 20;
        assert!(ftr.weights.contains(&test_weight) && ftr.weights.len() == 1);
        assert_eq!(ftr.weighted_servers[0], FromStr::from_str("127.0.0.1:8082").unwrap());
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
            assert_eq!(test_srv_pool.servers_map.get(&test_addr).unwrap().healthy, false);
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
