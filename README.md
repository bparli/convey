# Convey
Event-driven, layer 4 load balancer with dynamic configuration loading

## Features 
- Event-driven TCP load balancer built on [tokio].
- Weighted round-robin load balancing.  For uniform round robin simply leave out the weights or set them to be equal. 
- Stats page (at /stats) with basic connection/bytes counters and backend server pool statuses
- Dynamic configuration re-loading of backend servers and associated weights.  Configuration is loaded via a .toml file (see sample.toml for a full example).
- Tcp-based health checking of backend servers at a configured interval.  If a server fails its health check it will be automatically removed from selection and added back once its health checks are successful.

## Usage
```
Convey 0.1.0

Usage:
  convey
  convey --config=<config_file>
  convey (-h | --help)
  convey (-v | --version)

Options:
  -h, --help               Show this screen.
  --config=<config_file>   Config file location [default config.toml].
  -v, --version            Show version.
  ```


<!-- references -->
[tokio]: https://tokio.rs
