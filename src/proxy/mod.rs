extern crate tokio;

use futures::future::try_join;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

mod backend;

use self::backend::{get_next, run_health_checker, Backend, ServerPool};
use crate::config::{BaseConfig, Config};
use crate::stats::StatsMssg;

#[derive(Debug)]
pub struct Server {
    pub proxies: Vec<Arc<Proxy>>,

    rx: Receiver<BaseConfig>,
}

#[derive(Debug, Clone)]
pub struct Proxy {
    name: String,

    listen_addr: SocketAddr,

    backend: Arc<Backend>,
}

impl Server {
    pub fn new(config: Config) -> Server {
        let rcvr = config.clone().subscribe();
        let mut new_server = Server {
            proxies: Vec::new(),
            rx: rcvr,
        };
        for (name, front) in config.base.frontends.iter() {
            let mut backend_servers = HashMap::new();
            let mut health_check_interval = 5;
            match config.base.backends.get(&front.backend) {
                Some(back) => {
                    for (_, addr) in &back.servers {
                        let listen_addr: SocketAddr = FromStr::from_str(&addr.addr)
                            .ok()
                            .expect("Failed to parse listen host:port string");
                        backend_servers.insert(listen_addr, addr.weight);
                    }
                    if back.health_check_interval > 0 {
                        health_check_interval = back.health_check_interval;
                    }
                }
                None => {
                    error!("Error finding backend server pool in config: {} not found on backend config", front.backend);
                    continue;
                }
            };
            if backend_servers.len() > 0 {
                let listen_addr: SocketAddr = FromStr::from_str(&front.listen_addr)
                    .ok()
                    .expect("Failed to parse listen host:port string");

                let backend = Backend::new(
                    front.backend.clone(),
                    backend_servers,
                    health_check_interval,
                );
                let new_lb = Proxy {
                    name: name.clone(),
                    listen_addr: listen_addr,
                    backend: Arc::new(backend),
                };
                new_server.proxies.push(Arc::new(new_lb));
            } else {
                error!("Unable to configure load balancer server {:?}", front);
            }
        }
        new_server
    }

    // wait on config changes to update backend server pool
    async fn config_sync(&mut self) {
        loop {
            match self.rx.recv() {
                Ok(new_config) => {
                    debug!("Config file watch event. New config: {:?}", new_config);
                    for (backend_name, backend) in new_config.backends {
                        let mut backend_servers = HashMap::new();
                        for (_, server) in backend.servers {
                            let listen_addr: SocketAddr = FromStr::from_str(&server.addr)
                                .ok()
                                .expect("Failed to parse listen host:port string");
                            backend_servers.insert(listen_addr, server.weight);
                        }
                        let new_server_pool = ServerPool::new_servers(backend_servers);
                        for proxy in self.proxies.iter() {
                            if proxy.backend.name == backend_name {
                                info!(
                                    "Updating backend {} with {:?}",
                                    backend_name, new_server_pool
                                );
                                *proxy.backend.servers.write().await = new_server_pool.clone();
                            }
                        }
                    }
                }
                Err(e) => error!("watch error: {:?}", e),
            }
        }
    }

    #[tokio::main]
    pub async fn run(
        &mut self,
        sender: Sender<StatsMssg>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let proxies = self.proxies.clone();

        for proxy in proxies.iter() {
            // start background health checker for this proxy
            let health_sender = sender.clone();
            let back = proxy.backend.clone();
            tokio::spawn(async move {
                if let Err(e) = run_health_checker(back, health_sender).await {
                    error!("Error running health checker {}", e);
                    return;
                }
            });

            let srv_sender = sender.clone();
            let p = proxy.clone();
            tokio::spawn(async move {
                if let Err(e) = run_server(p.clone(), srv_sender).await {
                    error!("Error running proxy server {}: {:?}", e, p);
                    return;
                }
            });
        }
        self.config_sync().await;
        Ok(())
    }
}

async fn run_server(
    lb: Arc<Proxy>,
    sender: Sender<StatsMssg>,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Listening on: {:?}", lb.listen_addr);
    debug!("Proxying to: {:?}", lb.backend);

    let mut listener = TcpListener::bind(&lb.listen_addr).await?;

    while let Ok((inbound, _)) = listener.accept().await {
        // clones for async thread
        let sdr = sender.clone();
        let thread_lb = lb.clone();

        // and clones for updating stats thread in error condition
        let err_lb = lb.clone();
        let err_sdr = sender.clone();

        tokio::spawn(async move {
            if let Err(e) = process(inbound, sdr, thread_lb).await {
                error!("Failed to process tcp request; error={}", e);
                // update stats connections
                let mssg = StatsMssg {
                    frontend: Some(err_lb.name.clone()),
                    backend: err_lb.backend.name.clone(),
                    connections: -1,
                    bytes_tx: 0,
                    bytes_rx: 0,
                    servers: None,
                };
                match err_sdr.send(mssg) {
                    Ok(_) => {}
                    Err(e) => error!("Error sending stats message on channel: {}", e),
                }
            }
        });
    }
    Ok(())
}

async fn process(
    mut inbound: TcpStream,
    sender: Sender<StatsMssg>,
    lb: Arc<Proxy>,
) -> Result<(), Box<dyn std::error::Error>> {
    // update stats connections
    let mssg = StatsMssg {
        frontend: Some(lb.name.clone()),
        backend: lb.backend.name.clone(),
        connections: 1,
        bytes_tx: 0,
        bytes_rx: 0,
        servers: None,
    };
    match sender.send(mssg) {
        Ok(_) => {}
        Err(e) => error!("Error sending stats message on channel: {}", e),
    }

    let join = get_next(lb.backend.clone());
    match join.await {
        Some(server_addr) => {
            let mut server = TcpStream::connect(&server_addr).await?;

            let (mut ri, mut wi) = inbound.split();
            let (mut ro, mut wo) = server.split();

            let client_to_server = io::copy(&mut ri, &mut wo);
            let server_to_client = io::copy(&mut ro, &mut wi);

            let (bytes_tx, bytes_rx) = try_join(client_to_server, server_to_client).await?;

            debug!(
                "client wrote {:?} bytes and received {:?} bytes",
                bytes_tx, bytes_rx
            );

            // update stats connections and bytes
            let mssg = StatsMssg {
                frontend: Some(lb.name.clone()),
                backend: lb.backend.name.clone(),
                connections: -1,
                bytes_tx: bytes_tx,
                bytes_rx: bytes_rx,
                servers: None,
            };

            match sender.send(mssg) {
                Ok(_) => {}
                Err(e) => error!("Error sending stats message on channel: {}", e),
            }
        }
        None => error!("Unable to process request"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate hyper;
    use crate::config::Config;
    use crate::proxy;
    use hyper::rt::{self, Future};
    use hyper::service::service_fn_ok;
    use hyper::{Body, Request, Response, Server};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::sync::mpsc::channel;
    use std::thread;
    use std::time;
    use tokio::prelude::*;

    fn update_config(filename: &str, word_from: String, word_to: String) {
        let mut src = File::open(&filename).unwrap();
        let mut data = String::new();
        src.read_to_string(&mut data).unwrap();
        drop(src); // Close the file early

        // Run the replace operation in memory
        let new_data = data.replace(&*word_from, &*word_to);

        // Recreate the file and dump the processed contents to it
        let mut dst = File::create(&filename).unwrap();
        dst.write(new_data.as_bytes()).unwrap();
    }

    #[test]
    fn test_proxy() {
        thread::spawn(|| {
            let addr = ([127, 0, 0, 1], 8080).into();
            let server = Server::bind(&addr)
                .serve(|| {
                    service_fn_ok(move |_: Request<Body>| {
                        Response::new(Body::from("Success DummyA Server"))
                    })
                })
                .map_err(|e| eprintln!("server error: {}", e));
            rt::run(server);
        });

        thread::spawn(|| {
            let addr = ([127, 0, 0, 1], 8081).into();
            let server = Server::bind(&addr)
                .serve(|| {
                    service_fn_ok(move |_: Request<Body>| {
                        Response::new(Body::from("Success DummyB Server"))
                    })
                })
                .map_err(|e| eprintln!("server error: {}", e));
            rt::run(server);
        });

        let conf = Config::new("testdata/proxy_test.toml").unwrap();
        let mut lb = proxy::Server::new(conf);

        //TODO: verify messages sent over channel to stats endpoint from proxy
        let (tx, _) = channel();

        let tx = tx.clone();
        thread::spawn(move || {
            lb.run(tx).unwrap();
        });

        let secs = time::Duration::from_secs(2);
        thread::sleep(secs);

        // validate weighted scheduling
        for _ in 0..5 {
            let mut resp = reqwest::get("http://127.0.0.1:3000").unwrap();
            assert_eq!(resp.status(), 200);
            assert!(resp.text().unwrap().contains("DummyA"));
        }

        // update config to take DummyA out of service
        update_config(
            "testdata/proxy_test.toml",
            "weight = 10000".to_string(),
            "weight = 0".to_string(),
        );
        thread::sleep(secs);

        // validate only DummyB is serving requests now that DummyA has been taken out of service (weight set to 0)
        for _ in 0..5 {
            let mut resp = reqwest::get("http://127.0.0.1:3000").unwrap();
            assert_eq!(resp.status(), 200);
            assert!(resp.text().unwrap().contains("DummyB"));
        }

        // reset fixture
        update_config(
            "testdata/proxy_test.toml",
            "weight = 0".to_string(),
            "weight = 10000".to_string(),
        );
    }
}
