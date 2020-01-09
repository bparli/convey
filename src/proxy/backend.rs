use crate::stats::StatsMssg;
use rand::distributions::WeightedIndex;
use rand::prelude::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time;
use std::time::Duration;
use tokio::sync::RwLock;
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
    dist: Option<WeightedIndex<u16>>,
}

#[derive(Debug)]
pub struct Backend {
    pub name: String,
    pub servers: Arc<RwLock<ServerPool>>,
    pub health_check_interval: u64,
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
                None => {}
            }
            weighted_backend_servers.push(*server);
            if tcp_health_check(*server) {
                // server health check successful
                weights.push(server_weight);
                backend_servers.insert(
                    *server,
                    Wrr {
                        healthy: true,
                        weight: server_weight,
                        weights_index: index_count,
                    },
                );
            } else {
                // server health check not successful. set weight to 0
                weights.push(0);
                backend_servers.insert(
                    *server,
                    Wrr {
                        healthy: false,
                        weight: server_weight,
                        weights_index: index_count,
                    },
                );
            }

            index_count += 1;
        }
        debug!(
            "Created weighted backend server pool: {:?}",
            backend_servers
        );

        let mut servers_dist = None;
        match WeightedIndex::new(weights.clone()) {
            Ok(dist) => servers_dist = Some(dist),
            Err(e) => {
                error!(
                    "Unable to set weighted distribution for server pools: {:?}",
                    e
                );
                servers_dist = None;
            }
        }

        ServerPool {
            servers_map: backend_servers,
            weights: weights,
            weighted_servers: weighted_backend_servers,
            dist: servers_dist,
        }
    }
}

impl Backend {
    pub fn new(
        name: String,
        servers: HashMap<SocketAddr, Option<u16>>,
        health_check_interval: u64,
    ) -> Backend {
        Backend {
            name: name,
            servers: Arc::new(RwLock::new(ServerPool::new_servers(servers))),
            health_check_interval: health_check_interval,
        }
    }

    async fn update_backends_health(&self, updates: &HashMap<SocketAddr, bool>) {
        let mut srvs = self.servers.write().await;
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
                Ok(dist) => srvs.dist = Some(dist),
                Err(e) => {
                    error!("Unable to reset weighted distribution: {:?}", e);
                    srvs.dist = None;
                }
            }
        }
    }
}

pub async fn get_next(backend: Arc<Backend>) -> Option<SocketAddr> {
    let srvs = backend.servers.read().await;
    if let Some(dist) = &srvs.dist {
        if let Some(addr) = srvs.weighted_servers.get(dist.sample(&mut thread_rng())) {
            Some(*addr)
        } else {
            error!("Backend {} unhealthy; Unable to schedule", backend.name);
            None
        }
    } else {
        error!("Backend {} unhealthy; Unable to schedule", backend.name);
        None
    }
}

fn tcp_health_check(server: SocketAddr) -> bool {
    if let Ok(_) = TcpStream::connect_timeout(&server, time::Duration::from_secs(3)) {
        true
    } else {
        false
    }
}

pub async fn run_health_checker(
    back: Arc<Backend>,
    sender: Sender<StatsMssg>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut interval = tokio::time::interval(Duration::from_secs(back.health_check_interval));

    loop {
        let health_sender = sender.clone();
        let health_back = back.clone();
        debug!(
            "Running backend health checker{:?}, {:?}",
            health_back, interval
        );

        health_checker(health_back, health_sender).await?;
        interval.tick().await;
    }
}

async fn health_checker(
    backend: Arc<Backend>,
    sender: Sender<StatsMssg>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut backend_status = HashMap::new();
    let mut update = false;
    // limit scope of read lock
    {
        let srvs = backend.servers.read().await;
        for (server, status) in srvs.servers_map.iter() {
            let thread_server = server.clone();
            let join = task::spawn_blocking(move || tcp_health_check(thread_server));
            let res = join.await?;
            if res != status.healthy {
                info!(
                    "Server {} status has changed from {} to {}.  Updating stats and backend",
                    server, status.healthy, res
                );
                update = true;
            }
            backend_status.insert(server.clone(), res);
        }
    }

    // update_backends_health uses the write lock so only call it when absolutely necessary
    if update {
        backend.update_backends_health(&backend_status).await;
    }

    send_status(backend.name.clone(), backend_status, sender);
    Ok(())
}

fn send_status(name: String, updates: HashMap<SocketAddr, bool>, sender: Sender<StatsMssg>) {
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
    use std::{thread, time};
    use tokio::runtime;

    #[test]
    fn test_new_servers() {
        thread::spawn(|| {
            let listener = TcpListener::bind("127.0.0.1:8070").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {}
                Err(_e) => {}
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

        let test_srv = test_pool
            .servers_map
            .get(&FromStr::from_str("127.0.0.1:8071").unwrap())
            .unwrap();
        assert_eq!(test_srv.healthy, false);
        assert_eq!(test_srv.weight, 100);
    }

    #[test]
    fn test_backend() {
        thread::spawn(|| {
            let listener = TcpListener::bind("127.0.0.1:8090").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {}
                Err(_e) => {}
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

        let mut rt = runtime::Builder::new()
            .basic_scheduler()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(test_bck.update_backends_health(&test_updates));
        let test_pool = rt.block_on(test_bck.servers.read());
        let mut test_weight: u16 = 100;
        assert!(test_pool.weights.contains(&test_weight));
        test_weight = 1;
        assert!(test_pool.weights.contains(&test_weight));
    }

    #[test]
    fn test_get_next() {
        thread::spawn(|| {
            let listener = TcpListener::bind("127.0.0.1:8082").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {}
                Err(_e) => {}
            }
        });

        let one_sec = time::Duration::from_secs(1);
        thread::sleep(one_sec);

        let mut test_servers = HashMap::new();
        test_servers.insert(FromStr::from_str("127.0.0.1:8082").unwrap(), Some(20));
        let test_bck = Arc::new(Backend::new("test".to_string(), test_servers, 1000));

        let mut rt = runtime::Builder::new()
            .basic_scheduler()
            .enable_all()
            .build()
            .unwrap();

        let srv = rt.block_on(get_next(test_bck));
        assert_eq!(srv, Some(FromStr::from_str("127.0.0.1:8082").unwrap()));
    }

    #[test]
    fn test_srv_pool_health_checker() {
        let mut test_servers = HashMap::new();
        let test_addr = FromStr::from_str("127.0.0.1:8089").unwrap();
        test_servers.insert(test_addr, None);
        let mut rt = runtime::Builder::new()
            .basic_scheduler()
            .enable_all()
            .build()
            .unwrap();
        // not listening on 127.0.0.1:8089 yet so should be marked as unhealthy
        let test_bck = Backend::new("dummy".to_string(), test_servers.clone(), 1000);
        {
            let test_srv_pool = rt.block_on(test_bck.servers.read());
            //let test_srv_pool = test_bck.servers.read().unwrap();
            assert_eq!(
                test_srv_pool.servers_map.get(&test_addr).unwrap().healthy,
                false
            );
        }
        // start listening on 127.0.0.1:8089 so health checks will mark as healthy
        thread::spawn(|| {
            let listener = TcpListener::bind("127.0.0.1:8089").unwrap();
            match listener.accept() {
                Ok((_socket, _addr)) => {}
                Err(_e) => {}
            }
        });
        let one_sec = time::Duration::from_secs(1);
        thread::sleep(one_sec);
        let test_bck = Backend::new("dummy".to_string(), test_servers, 1000);
        {
            let test_srv_pool = rt.block_on(test_bck.servers.read());
            //let test_srv_pool = test_bck.servers.read().unwrap();
            assert_eq!(
                test_srv_pool.servers_map.get(&test_addr).unwrap().healthy,
                true
            );
        }
    }
}
