# Convey
Layer 4 load balancer with dynamic configuration loading featuring proxy, passthrough and disrect server return modes

## Features
- Stats page (at /stats) with basic connection/bytes counters and backend server pool statuses
- Dynamic configuration re-loading of backend servers and associated weights.  Configuration is loaded via a .toml file (see sample.toml for a full example).
- Tcp-based health checking of backend servers at a configured interval.  If a server fails its health check it will be automatically removed from selection and added back once its health checks are successful.

### Proxy Features
- Event-driven TCP load balancer built on [tokio].
- Weighted round-robin load balancing.  For uniform round robin simply leave out the weights or set them to be equal.
- TCP connection termination

### Passthrough and Direct Server Return (DSR) Features
- Packet forwarding (no TCP termination)
- Minimal internal connection tracking
- NAT

## Usage
```
Convey 0.2.0

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
  ```

### Passthrough mode
For passthrough mode we need a couple iptables rules on the convey load balancer to handle ingress packets from the client and responses from the backend load balanced servers.  Since TCP is not terminating we need to ensure the OS does not send a RST in response to any packets destined for a port that does not have a process bound to it.  We need to do the same for any packets came back through from a backend server.  Convey internally assigns ephemeral ports 32768-61000 to map connections to clients.

![passthrough](https://docs.google.com/drawings/d/e/2PACX-1vS1umK8iY4EryR0hV4s1lad2r5BrO4_nbFTCua9jqkPP7fSQXodXCZ8XD7kvkfeXxdphtMFczIij-K1/pub?w=581&h=326)

For passthrough mode on the convey load balancer
``` 
sudo iptables -t raw -A PREROUTING -p tcp --dport <LOAD_BALANCER_PORT> -j DROP
sudo iptables -t raw -A PREROUTING -p tcp --sport <BACKEND_SERVER_PORT> --dport 32768:61000 -j DROP
```

To run
```
sudo ./target/release/convey --passthrough --config=sample-passthrough.toml
```

### DSR Mode
For dsr mode we need the same iptables rule for ingress packets.  Responses from the backend load balanced servers will be going directly to the clients.  The "listening" port on the convey load balancer must match the backend load balanced servers listening ports in this mode.

![dsr](https://docs.google.com/drawings/d/e/2PACX-1vTkBC0326E1hZwRw_KBbdiP3npNL_2KGq2QdUiS2J05xX1y5uhKIDegpEmviyvBWz4NmHbgVTB6jmsq/pub?w=581&h=326)

For dsr mode on the convey load balancer
```
sudo iptables -t raw -A PREROUTING -p tcp --dport <LOAD_BALANCER_PORT> -j DROP
```

In dsr mode the backend servers "participate" in that their response packets must be sent directly to the client.  Convey does not do any encapsulation so, for example, a gre tunnel is not an option.  Instead, [Traffic Control] can be used as an egress nat.

For dsr mode on backend servers
```
sudo tc qdisc add dev enp0s8 root handle 10: htb

sudo tc filter add dev enp0s8 parent 10: protocol ip prio 1 u32 match ip src <LOCAL_SERVER_IP> match ip sport <LISTEN_PORT> 0xffff match ip dst <LOAD_BALANCER_IP> action ok

sudo tc filter add dev enp0s8 parent 10: protocol ip prio 10 u32 match ip src <LOCAL_SERVER_IP> match ip sport <LISTEN_PORT> 0xffff action nat egress 192.168.1.117 <LOAD_BALANCER_IP>
``` 

To run
```
sudo ./target/release/convey --dsr --config=sample-passthrough.toml
```

### Proxy 
No special setup neccessary

![proxy](https://docs.google.com/drawings/d/e/2PACX-1vQC7fAvVEs0Xb0kcAFfCLIVukhkIrlu-DS_tbrtgpRonmsHO9STpnXvI7NogXiBVUON9gS-L4MLqYV2/pub?w=581&h=326)

To run
```
sudo ./target/release/convey --config=sample-proxy.toml
```

## Tests
The easiest way to run tests is to run them as superuser.  This is because some of the tests spin up test servers as well as a convey load balancer instance.
```
sudo ~/.cargo/bin/cargo test
```

## Build
```cargo build --release```

<!-- references -->
[tokio]: https://tokio.rs
[Traffic Control]: http://tldp.org/HOWTO/Traffic-Control-HOWTO/index.html

