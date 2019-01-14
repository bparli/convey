#[macro_use]
extern crate log;
extern crate env_logger;
extern crate toml;
#[macro_use]
extern crate serde_derive;

mod config;
mod stats;
mod proxy;
mod passthrough;

use docopt::Docopt;
use self::config::Config;


const USAGE: &'static str = "
Convey 0.1.1

Usage:
  convey
  convey --config=<config_file>
  convey --workers=<NUM_WORKERS>
  convey (-p | --passthrough) --config=<config_file> --workers=<NUM_WORKERS>
  convey (-p | --passthrough) --workers=<NUM_WORKERS>
  convey (-p | --passthrough) --config=<config_file>
  convey (-p | --passthrough)
  convey (-h | --help)
  convey (-v | --version)

Options:
  -h, --help               Show this screen.
  -p, --passthrough        Run load balancer in passthrough mode (instead of default proxy mode)
  --config=<config_file>   Config file location [default config.toml].
  -v, --version            Show version.
  --workers=<NUM_WORKERS>             Number of worker threads in passthrough mode
";

fn main() {
    env_logger::init();
    let version = "0.1.0".to_owned();
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
                let mut num_workers = 4;
                if args.get_count("--workers") > 0 {
                    num_workers = args.get_count("--workers");
                }
                debug!("Starting loadbalancer in passthrough mode");
                let loadbalancer = passthrough::Server::new(config);
                loadbalancer.run(stats_sender, num_workers);
            } else {
                debug!("Starting loadbalancer in proxy mode");
                let loadbalancer = proxy::Server::new(config);
                loadbalancer.run(stats_sender);
            }
        },
        Err(e) => error!("Error loading configuration file: {:?}", e)
    }
}
