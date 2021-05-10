use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Error as IOError, Read};
use std::result::Result;
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    filename: String,
    pub base: BaseConfig,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct BaseConfig {
    pub frontends: HashMap<String, FrontendConfig>,
    pub backends: HashMap<String, BackendPool>,
    pub stats: Stats,
    pub passthrough: Option<Passthrough>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Stats {
    pub port: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct FrontendConfig {
    pub listen_addr: String,
    pub backend: String,
    pub xdp: Option<XdpConfig>,
}
#[derive(Debug, Deserialize, Default, Clone)]
pub struct XdpConfig {
    pub bpf_program_path: String,
    pub progsec_name: String,
    pub xsks_map_name: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct BackendPool {
    pub servers: HashMap<String, ServerConfig>,
    pub health_check_interval: u64,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ServerConfig {
    pub addr: String,
    pub weight: Option<u16>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy)]
pub struct Passthrough {
    pub connection_tracker_capacity: usize,
    pub workers: Option<usize>,
    pub stats_update_frequency: Option<u64>,
}

#[derive(Debug)]
pub enum ReadError {
    IOError(IOError),
    ParseError(Vec<toml::de::Error>),
    DecodeError(toml::de::Error),
}

impl Config {
    pub fn new(filename: &str) -> Result<Config, ReadError> {
        let decoded = (load_config(filename))?;
        Ok(Config {
            filename: filename.to_string(),
            base: decoded,
        })
    }

    fn reload(self) -> Result<BaseConfig, ReadError> {
        load_config(self.filename.as_str())
    }

    pub fn subscribe(self) -> Receiver<BaseConfig> {
        let filename = self.filename.clone();
        let (config_tx, config_rx) = channel();
        let config_tx = config_tx.clone();
        thread::spawn(move || {
            let (tx, rx) = channel();
            let watcher: Result<RecommendedWatcher, notify::Error> =
                Watcher::new(tx, Duration::from_secs(2));
            match watcher {
                Ok(mut w) => match w.watch(filename, RecursiveMode::NonRecursive) {
                    Ok(_) => loop {
                        match rx.recv() {
                            Ok(event) => {
                                debug!("config file watch event {:?}", event);
                                match self.clone().reload() {
                                    Ok(new_config) => match config_tx.send(new_config) {
                                        Ok(_) => {}
                                        Err(e) => error!("Error sending re-loaded config {:?}", e),
                                    },
                                    Err(e) => error!("Unable to re-load new configuration {:?}", e),
                                }
                            }
                            Err(e) => error!("watch error: {:?}", e),
                        }
                    },
                    Err(e) => error!("Error initializing config file watcher {}", e),
                },
                Err(e) => error!("Error initializing config file watcher {}", e),
            }
        });
        config_rx
    }
}

fn load_config(filename: &str) -> Result<BaseConfig, ReadError> {
    let mut contents = String::new();
    let mut file = (File::open(filename))?;
    (file.read_to_string(&mut contents))?;

    let decoded: BaseConfig = toml::from_str(&contents)?;
    Ok(decoded)
}

impl From<IOError> for ReadError {
    fn from(e: IOError) -> ReadError {
        ReadError::IOError(e)
    }
}

impl From<toml::de::Error> for ReadError {
    fn from(e: toml::de::Error) -> ReadError {
        ReadError::DecodeError(e)
    }
}

impl From<Vec<toml::de::Error>> for ReadError {
    fn from(e: Vec<toml::de::Error>) -> ReadError {
        ReadError::ParseError(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::prelude::*;
    use std::{thread, time};

    #[test]
    fn test_new_config() {
        match Config::new("testdata/test.toml") {
            Ok(config) => {
                assert!(config.filename == "testdata/test.toml".to_string());
                let test_front = config.base.frontends.get("tcp_3000").unwrap();
                assert!(test_front.listen_addr == "0.0.0.0:3000".to_string());
            }
            Err(_) => assert!(false),
        }

        assert!(
            Config::new("testdata/bad.toml").is_err(),
            "Config file is not valid"
        );
    }

    #[test]
    fn test_subscribe() {
        let conf = Config::new("testdata/test.toml").unwrap();
        let rx = conf.subscribe();

        let one_secs = time::Duration::from_secs(1);
        thread::sleep(one_secs);

        {
            let mut f = OpenOptions::new()
                .write(true)
                .append(true)
                .open("testdata/test.toml")
                .unwrap();
            f.write_all(b"\n").unwrap();
            f.sync_data().unwrap();
        }

        let three_secs = time::Duration::from_secs(3);
        thread::sleep(three_secs);

        match rx.try_recv() {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }
}
