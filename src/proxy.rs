extern crate tokio;

use std::sync::{Arc, Mutex};
use std::net::{Shutdown, SocketAddr};
use std::io::{self, Read, Write};
use std::str::FromStr;
use tokio::io::{copy, shutdown};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::timer::Interval;
use std::time::{Duration, Instant};
use futures::future::lazy;
use std::sync::mpsc::{Sender, Receiver};
use std::collections::HashMap;
use std::thread;

use crate::backend::{Backend, ServerPool, health_checker, get_next};
use crate::config::{Config, BaseConfig};
use crate::stats::StatsMssg;

#[derive(Debug, Clone)]
pub struct Server {
    pub proxies: Vec<Proxy>,
}

#[derive(Debug, Clone)]
pub struct Proxy {
    name: String,

    listen_addr: SocketAddr,

    backend: Arc<Backend>,
}

impl Server {
    pub fn new(config: Config) -> Server {
        let mut new_server = Server {proxies: Vec::new()};
        for (name,front) in config.base.frontends.iter() {
            let mut backend_servers = HashMap::new();
            let mut health_check_interval = 5;
            match config.base.backends.get(&front.backend) {
                Some(back) => {
                    for (_,addr) in &back.servers {
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
                    continue
                },
            };
            if backend_servers.len() > 0 {
                let listen_addr: SocketAddr = FromStr::from_str(&front.listen_addr)
                                  .ok()
                                  .expect("Failed to parse listen host:port string");

                let backend = Arc::new(Backend::new(front.backend.clone(), backend_servers, health_check_interval));
                let new_lb = Proxy {
                    name: name.clone(),
                    listen_addr: listen_addr,
                    backend: backend.clone(),
                };
                new_server.proxies.push(new_lb);
            } else {
                error!("Unable to configure load balancer server {:?}", front);
            }
        }

        let rx = config.subscribe();
        new_server.config_sync(rx);
        new_server
    }

    // wait on config changes to update backend server pool
    fn config_sync(&mut self, rx: Receiver<BaseConfig>) {
        let proxies = self.proxies.clone();
        thread::spawn( move || {
            loop {
                match rx.recv() {
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
                            for proxy in proxies.iter() {
                                if proxy.backend.name == backend_name {
                                    info!("Updating backend {} with {:?}", backend_name, new_server_pool);
                                    *proxy.backend.servers.write().unwrap() = new_server_pool.clone();
                                }
                            }
                        }
                    }
                    Err(e) => error!("watch error: {:?}", e),
                }
            }
        });
    }

    pub fn run(self, sender: Sender<StatsMssg>) {
        tokio::run(lazy( move || {
            for proxy in self.proxies.iter() {
                match run_server(proxy.clone(), sender.clone()) {
                    Ok(_) => {},
                    Err(e) => error!("Error binding to socket {}", e),
                }
            }
            Ok(())
        }));
    }
}

fn run_server(lb: Proxy, sender: Sender<StatsMssg>) -> Result<(), Box<std::error::Error>>{
    debug!("Listening on: {:?}", lb.listen_addr);
    debug!("Proxying to: {:?}", lb.backend);
    match TcpListener::bind(&lb.listen_addr) {
        Ok(socket) => {

            // schedule health checker
            let back = lb.backend.clone();
            let time = back.health_check_interval;
            let timer_sender = sender.clone();
            let task = Interval::new(Instant::now(), Duration::from_secs(time))
                .for_each(move |instant| {
                    health_checker(back.clone(), &timer_sender);
                    debug!("Running backend health checker{:?}", instant);
                    Ok(())
                })
                .map_err(|e| panic!("interval errored; err={:?}", e));
            tokio::spawn(task);

            let done = socket.incoming()
                .map_err(|e| error!("error accepting socket; error = {:?}", e))
                .for_each(move |client| {

                    let server_addr = get_next(lb.backend.clone());
                    let server = server_addr.and_then(move |server_addr| {
                        TcpStream::connect(&server_addr)
                    });

                    // update stats connections
                    let mssg = StatsMssg{frontend: Some(lb.name.clone()),
                                        backend: lb.backend.name.clone(),
                                        connections: 1,
                                        bytes_tx: 0,
                                        bytes_rx: 0,
                                        servers: None};
                    match sender.send(mssg) {
                        Ok(_) => {},
                        Err(e) => error!("Error sending stats message on channel: {}", e)
                    }

                    let amounts = server.and_then(move |server| {
                        let client_reader = MyTcpStream(Arc::new(Mutex::new(client)));
                        let client_writer = client_reader.clone();
                        let server_reader = MyTcpStream(Arc::new(Mutex::new(server)));
                        let server_writer = server_reader.clone();

                        // Copy the data (in parallel) between the client and the server.
                        // After the copy is done we indicate to the remote side that we've
                        // finished by shutting down the connection.
                        let client_to_server = copy(client_reader, server_writer)
                            .and_then(|(n, _, server_writer)| {
                                shutdown(server_writer).map(move |_| n)
                            });

                        let server_to_client = copy(server_reader, client_writer)
                            .and_then(|(n, _, client_writer)| {
                                shutdown(client_writer).map(move |_| n)
                            });

                        client_to_server.join(server_to_client)
                    });

                    let thread_sender = sender.clone();
                    let frontend_name = lb.name.clone();
                    let backend_name = lb.backend.name.clone();
                    let msg = amounts.map(move |(from_client, from_server)| {
                        debug!("client wrote {} bytes and received {} bytes",
                                 from_client, from_server);

                        // update stats connections and bytes
                        let mssg = StatsMssg{
                                        frontend: Some(frontend_name),
                                        backend: backend_name,
                                        connections: -1,
                                        bytes_tx: from_client,
                                        bytes_rx: from_server,
                                        servers: None};
                        match thread_sender.send(mssg) {
                            Ok(_) => {},
                            Err(e) => error!("Error sending stats message on channel: {}", e)
                        }
                    }).map_err(|e| {
                        // Don't panic. Maybe the client just disconnected too soon.
                        error!("error: {}", e);
                    });

                    tokio::spawn(msg);
                    Ok(())
                });
            tokio::spawn(done);
            Ok(())
        }
        Err(e) => Result::Err(Box::new(e))
    }
}

// From tokio proxy example
// This is a custom type used to have a custom implementation of the
// `AsyncWrite::shutdown` method which actually calls `TcpStream::shutdown` to
// notify the remote end that we're done writing.
#[derive(Clone)]
struct MyTcpStream(Arc<Mutex<TcpStream>>);

impl Read for MyTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
}

impl Write for MyTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for MyTcpStream {}

impl AsyncWrite for MyTcpStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        (self.0.lock().unwrap().shutdown(Shutdown::Write))?;
        Ok(().into())
    }
}


#[cfg(test)]
mod tests {
    extern crate hyper;
    use super::*;
    use std::sync::mpsc::channel;
    use std::thread;
    use crate::config::{Config};
    use crate::proxy;
    use hyper::{Body, Request, Response, Server};
    use hyper::service::service_fn_ok;
    use hyper::rt::{self, Future};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::{time};

    fn update_config(filename: &str, word_from: String, word_to: String) {
        let mut src = File::open(&filename).unwrap();
        let mut data = String::new();
        src.read_to_string(&mut data).unwrap();
        drop(src);  // Close the file early

        // Run the replace operation in memory
        let new_data = data.replace(&*word_from, &*word_to);

        // Recreate the file and dump the processed contents to it
        let mut dst = File::create(&filename).unwrap();
        dst.write(new_data.as_bytes()).unwrap();
    }

    #[test]
    fn test_proxy() {
        thread::spawn( ||{
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

        thread::spawn( ||{
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
        let lb = proxy::Server::new(conf);

        //TODO: verify messages sent over channel to stats endpoint from proxy
        let (tx, _) = channel();

        let tx = tx.clone();
        thread::spawn( ||{
            lb.run(tx);
        });

        // validate weighted scheduling
        for _ in 0..10 {
            let mut resp = reqwest::get("http://127.0.0.1:3000").unwrap();
            assert_eq!(resp.status(), 200);
            assert!(resp.text().unwrap().contains("DummyA"));
        }

        // update config to take DummyA out of service
        update_config("testdata/proxy_test.toml", "weight = 10000".to_string(), "weight = 0".to_string());
        let two_secs = time::Duration::from_secs(2);
        thread::sleep(two_secs);

        // validate only DummyB is serving requests now that DummyA has been taken out of service (weight set to 0)
        for _ in 0..10 {
            let mut resp = reqwest::get("http://127.0.0.1:3000").unwrap();
            assert_eq!(resp.status(), 200);
            assert!(resp.text().unwrap().contains("DummyB"));
        }

        // reset fixture
        update_config("testdata/proxy_test.toml", "weight = 0".to_string(), "weight = 10000".to_string());
    }
}
