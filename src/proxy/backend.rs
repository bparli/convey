use std::net::SocketAddr;
use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::{Arc, RwLock};
use crate::stats::StatsMssg;
use std::sync::mpsc::{channel, Sender};
use rand::distributions::{WeightedIndex, WeightedError};
use rand::prelude::*;
use std::time;
use std::io::{Error, ErrorKind};
use std::time::{Duration};
use tokio::task;

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
    dist: WeightedIndex<u16>,
}

#[derive(Debug)]
pub struct Backend {
    pub name: String,
    pub servers: Arc<RwLock<ServerPool>>,
    pub health_check_interval: u64,
}

impl ServerPool {
    pub fn new_servers(servers: HashMap<SocketAddr, Option<u16>>) -> Result<ServerPool, WeightedError> {
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

        match WeightedIndex::new(&weights) {
            Ok(dist) => {
                let servers = ServerPool {
                    servers_map: backend_servers,
                    weights: weights,
                    weighted_servers: weighted_backend_servers,
                    dist: dist,
                };
                Ok(servers)
            }
            Err(e) => {
                error!("Unable to set weighted distribution for server pools: {:?}", e);
                Err(e)
            }
        }
    }
}

impl Backend {
    pub fn new(name: String, servers: HashMap<SocketAddr, Option<u16>>, health_check_interval: u64) -> Result<Backend, Error>{
        match ServerPool::new_servers(servers) {
            Ok(backend_servers) => {
                Ok(Backend {
                    name: name,
                    servers: Arc::new(RwLock::new(backend_servers)),
                    health_check_interval: health_check_interval,
                })
            }
            Err(_) => Err(Error::new(ErrorKind::Other, "Unable to create server pool"))
        }
    }

    fn update_backends_health(&self, updates: &HashMap<SocketAddr, bool>) {
        let mut srvs = self.servers.write().unwrap();
        let mut wgts = srvs.weights.clone();

        let mut reset_dist = false;
        for (srv, healthy) in updates {
            if let Some(s) = srvs.servers_map.get_mut(&srv) {
                s.healthy = *healthy;
                reset_dist = true;
                if *healthy {
                    wgts[s.weights_index] = s.weight;
                } else {
                    wgts[s.weights_index] = 0;
                }
            }
        }
        srvs.weights = wgts;
        if reset_dist {
            match WeightedIndex::new(srvs.weights.clone()) {
                Ok(dist) => srvs.dist = dist,
                Err(e) => error!("Unable to reset weighted distribution: {:?}", e)
            }
        }
    }
}

pub fn get_next(backend: Arc<Backend>) -> Option<SocketAddr> {
    match backend.servers.read() {
        Ok(srvs) => {
            if let Some(addr) = srvs.weighted_servers.get(srvs.dist.sample(&mut thread_rng())) {
                Some(*addr)
            } else{
                error!("Unable to schedule backend");
                None
            }
        }
        Err(e) => {
            error!("Unable to schedule backend: {:?}", e);
            None
        }
    }
}

fn tcp_health_check(server: SocketAddr) -> bool {
    if let Ok(_) = TcpStream::connect_timeout(&server, time::Duration::from_secs(3)) {
        true
    } else {
        false
    }
}

pub async fn run_health_checker(back: Arc<Backend>, sender: Sender<StatsMssg>) -> Result<(), Box<dyn std::error::Error>> {
    let mut interval = tokio::time::interval(Duration::from_secs(back.health_check_interval));

    loop {
        let health_sender = sender.clone();
        let health_back = back.clone();
        debug!("Running backend health checker{:?}", interval);

        task::spawn_blocking(|| {
            health_checker(health_back, health_sender)
        });

        interval.tick().await;
    }
}

fn health_checker(backend: Arc<Backend>, sender: Sender<StatsMssg>) {
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

fn send_status(name: String, updates: HashMap<SocketAddr, bool>, sender: Sender<StatsMssg>) {
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

        let test_pool = ServerPool::new_servers(test_servers).unwrap();

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

        let test_bck = Backend::new("test".to_string(), test_servers, 1000).unwrap();
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
        let test_bck = Arc::new(Backend::new("test".to_string(), test_servers, 1000).unwrap());

        let svr = get_next(test_bck);
        assert_eq!(svr, Some(FromStr::from_str("127.0.0.1:8082").unwrap()));
    }

    #[test]
    fn test_srv_pool_health_checker() {
        let mut test_servers = HashMap::new();
        let test_addr = FromStr::from_str("127.0.0.1:8089").unwrap();
        test_servers.insert(test_addr, None);

        // listening on 127.0.0.1:8089 yet so should be marked as healthy
        match Backend::new("dummy".to_string(), test_servers.clone(), 1000) {
            Ok(_) => assert!(false),
            Err(_) => assert!(true), // health checks should not pass
        }

        // start listening on 127.0.0.1:8089 so health checks will mark as healthy
        thread::spawn( ||{
            let listener = TcpListener::bind("127.0.0.1:8089").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {},
                Err(_e) => {},
            }
        });
        let one_sec = time::Duration::from_secs(1);
        thread::sleep(one_sec);

        let test_bck = Backend::new("dummy".to_string(), test_servers, 1000).unwrap();
        {
            let test_srv_pool = test_bck.servers.read().unwrap();
            assert_eq!(test_srv_pool.servers_map.get(&test_addr).unwrap().healthy, true);
        }
    }
}
