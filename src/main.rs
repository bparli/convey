#[macro_use]
extern crate log;
extern crate env_logger;
extern crate toml;
#[macro_use]
extern crate serde_derive;

mod config;
mod passthrough;
mod proxy;
mod stats;

use self::config::Config;
use docopt::Docopt;

const USAGE: &'static str = "
Convey 0.3.3

Usage:
  convey
  convey --config=<config_file>
  convey (-p | --passthrough) --config=<config_file>
  convey (-d | --dsr) --config=<config_file>
  convey (-p | --passthrough)
  convey (-d | --dsr)
  convey (-h | --help)
  convey (-v | --version)

Options:
  -h, --help               Show this screen.s
  -p, --passthrough        Run load balancer in passthrough mode (instead of default proxy mode)
  -d, --dsr                Run load balancer in direct server mode (instead of default proxy mode)
  --config=<config_file>   Config file location [default config.toml].
  -v, --version            Show version.
";

fn main() {
    env_logger::init();
    let version = "0.3.3".to_owned();
    let args = Docopt::new(USAGE)
        .and_then(|dopt| dopt.version(Some(version)).parse())
        .unwrap_or_else(|e| e.exit());
    println!("{:?}", args);

    let mut config_file = "config.toml";
    if args.get_str("--config") != "" {
        config_file = args.get_str("--config");
    }
    println!("{:?}", config_file);

    let config = Config::new(&config_file);
    match config {
        Ok(config) => {
            info!("Config is: {:?}", config);
            let stats_sender = stats::run(&config.base);
            if args.get_bool("--passthrough") {
                debug!("Starting loadbalancer in passthrough mode");
                let mut loadbalancer = passthrough::Server::new(config, false);
                loadbalancer.run(stats_sender);
            } else if args.get_bool("--dsr") {
                debug!("Starting loadbalancer in direct server return mode");
                let mut loadbalancer = passthrough::Server::new(config, true);
                loadbalancer.run(stats_sender);
            } else {
                debug!("Starting loadbalancer in proxy mode");
                let mut loadbalancer = proxy::Server::new(config);
                if let Err(_) = loadbalancer.run(stats_sender) {
                    error!("Unable to start server");
                }
            }
        }
        Err(e) => error!("Error loading configuration file: {:?}", e),
    }
}
