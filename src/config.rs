use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Error as IOError};
use std::result::Result;
use std::sync::mpsc::{Receiver};
use std::thread;

extern crate notify;

use notify::{RecommendedWatcher, Watcher, RecursiveMode};
use std::sync::mpsc::channel;
use std::time::Duration;

use toml;

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
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Stats {
    pub port: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct FrontendConfig {
    pub listen_addr: String,
    pub backend:     String,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct BackendPool {
    pub servers:    HashMap<String, ServerConfig>,
    pub health_check_interval:   u64,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ServerConfig {
    pub addr:    String,
    pub weight: Option<u16>,
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
        Ok(Config{filename: filename.to_string(), base: decoded})
    }

    fn reload(self) -> Result<BaseConfig, ReadError> {
        load_config(self.filename.as_str())
    }

    pub fn subscribe(self) -> Receiver<BaseConfig> {
        let filename = self.filename.clone();
        let (config_tx, config_rx) = channel();
        let config_tx = config_tx.clone();
        thread::spawn( move || {
            let (tx, rx) = channel();
            let watcher: Result<RecommendedWatcher, notify::Error> = Watcher::new(tx, Duration::from_secs(2));
            match watcher {
                Ok(mut w) => {
                    match w.watch(filename, RecursiveMode::NonRecursive) {
                        Ok(_) => {
                            loop {
                                match rx.recv() {
                                    Ok(event) => {
                                        debug!("config file watch event {:?}", event);
                                        match self.clone().reload(){
                                            Ok(new_config) => {
                                                match config_tx.send(new_config) {
                                                    Ok(_) => {},
                                                    Err(e) => error!("Error sending re-loaded config {:?}", e),
                                                }
                                            }
                                            Err(e) => error!("Unable to re-load new configuration {:?}", e),
                                        }
                                    }
                                    Err(e) => println!("watch error: {:?}", e),
                                }
                            }
                        }
                        Err(e) => error!("Error initializing config file watcher {}", e),
                    }
                }
                Err(e) => error!("Error initializing config file watcher {}", e),
            }
        });
        config_rx
    }
}

fn load_config(filename: &str) -> Result<BaseConfig, ReadError>{
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
