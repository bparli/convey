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
    if let Ok(_) = TcpStream::connect(server) {
        true
    } else {
        false
    }
}

pub fn health_checker(backend: Arc<Backend>, sender: &Sender<StatsMssg>) {
    let mut backend_status = HashMap::new();
    let mut update = false;
    {
        let srvs = backend.servers.read().unwrap();
        for (server, status) in srvs.servers_map.iter() {
            let res = tcp_health_check(*server);
            if res != status.healthy {
                debug!("Server {} status has changed from {} to {}.  Updating stats and backend", server, status.healthy, res);
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
