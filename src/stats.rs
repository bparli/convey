extern crate router;
extern crate serde_json;
extern crate iron;

use iron::{Handler, Iron, Request, Response, IronResult, status, mime};
use router::Router;
use std::sync::{Arc, RwLock};
use std::thread;
use crate::config::BaseConfig;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::collections::BTreeMap;

pub struct StatsMssg {
    pub frontend: Option<String>,
    pub backend: String,
    pub connections: i32,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub healthy: Option<bool>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StatsApi {
    stats: Arc<RwLock<Stats>>,
}

#[derive(Serialize)]
struct Stats {
    total_connections: i32,
    current_connections: i32,
    total_bytes_tx: u64,
    total_bytes_rx: u64,
    backends: BTreeMap<String, BackendStats>,
    frontends: BTreeMap<String, FrontendStats>,
}

#[derive(Serialize)]
struct BackendStats {
    total_connections: i32,
    current_connections: i32,
    bytes_tx: u64,
    bytes_rx: u64,
    healthy: bool,
}

#[derive(Serialize)]
struct FrontendStats {
    total_connections: i32,
    current_connections: i32,
    bytes_tx: u64,
    bytes_rx: u64,
}

impl Handler for StatsApi {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        let content_type = "application/json".parse::<mime::Mime>().unwrap();
        let serialized = serde_json::to_string(&self.stats.clone()).unwrap();
        Ok(Response::with((content_type, status::Ok, serialized)))
    }
}

pub fn run(lb_config: &BaseConfig) -> Sender<StatsMssg> {
    let (sender, receiver): (Sender<StatsMssg>, Receiver<StatsMssg>) = channel();
    let mut frontends = BTreeMap::new();
    let mut backends = BTreeMap::new();
    for (name, _) in &lb_config.frontends {
        let front = FrontendStats {
            total_connections: 0,
            current_connections: 0,
            bytes_rx: 0,
            bytes_tx: 0,
        };
        frontends.insert(name.clone(), front);
    }
    for (name, _) in &lb_config.backends {
        let back = BackendStats {
            total_connections: 0,
            current_connections: 0,
            bytes_rx: 0,
            bytes_tx: 0,
            healthy: false,
        };
        backends.insert(name.clone(), back);
    }

    let stats = Arc::new(RwLock::new(Stats {
        total_connections: 0,
        current_connections: 0,
        total_bytes_rx: 0,
        total_bytes_tx: 0,
        frontends: frontends,
        backends: backends,
    }));

    let handler = StatsApi {
        stats: stats.clone(),
    };
    let mut router = Router::new();
    router.get("/stats", handler, "handler");
    let stats_addr = format!("0.0.0.0:{}", lb_config.stats.port);
    thread::spawn(move ||{
        match Iron::new(router).http(&stats_addr) {
            Ok(_) => info!("Started stats api on {}/stats", &stats_addr),
            Err(e) => error!("Error started stats api {}", e),
        }
    });

    let thread_stats = stats.clone();
    thread::spawn(move ||{
        loop {
            match receiver.recv() {
                Ok(mssg) => {
                    let mut new_stats = thread_stats.write().unwrap();
                    new_stats.current_connections = new_stats.current_connections + mssg.connections;
                    if  mssg.connections > 0 {
                        new_stats.total_connections = new_stats.total_connections + mssg.connections;
                    }
                    new_stats.total_bytes_rx = new_stats.total_bytes_rx + mssg.bytes_rx;
                    new_stats.total_bytes_tx = new_stats.total_bytes_tx + mssg.bytes_tx;

                    if let Some(mut backend_stats) = new_stats.backends.get_mut(&mssg.backend) {
                        backend_stats.current_connections = backend_stats.current_connections + mssg.connections;
                        if  mssg.connections > 0{
                            backend_stats.total_connections = backend_stats.total_connections + mssg.connections;
                        }
                        backend_stats.bytes_rx = backend_stats.bytes_rx + mssg.bytes_rx;
                        backend_stats.bytes_tx = backend_stats.bytes_tx + mssg.bytes_tx;

                        if let Some(healthy) = &mssg.healthy {
                            backend_stats.healthy = *healthy;
                        }
                    }

                    if let Some(frontend_name) = &mssg.frontend {
                        if let Some(mut frontend_stats) = new_stats.frontends.get_mut(frontend_name) {
                            frontend_stats.current_connections = frontend_stats.current_connections + mssg.connections;
                            if  mssg.connections > 0{
                                frontend_stats.total_connections = frontend_stats.total_connections + mssg.connections;
                            }
                            frontend_stats.bytes_rx = frontend_stats.bytes_rx + mssg.bytes_rx;
                            frontend_stats.bytes_tx = frontend_stats.bytes_tx + mssg.bytes_tx;
                        }
                    }
                },
                Err(e) => {
                    error!("An error occurred while reading: {}", e);
                }
            }
        }
    });
    sender
}
