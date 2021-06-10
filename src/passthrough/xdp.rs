use arraydeque::{ArrayDeque, Wrapping};
use rebpf::{error as rebpf_error, interface, libbpf};
use std::cmp::min;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{mpsc::Sender, Arc, Mutex};
use std::thread;
use std::time::Duration;

use super::arp::Arp;
use super::lb::LB;
use crate::stats::StatsMssg;
use afxdp::mmap_area::{MmapArea, MmapAreaOptions};
use afxdp::socket::{Socket, SocketOptions, SocketRx, SocketTx};
use afxdp::umem::{Umem, UmemCompletionQueue, UmemFillQueue};
use afxdp::PENDING_LEN;
use afxdp::{buf::Buf, buf_pool::BufPool};
use afxdp::{buf_mmap::BufMmap, buf_pool_vec::BufPoolVec};
use libbpf_sys::{XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS};
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use pnet::packet::ethernet::EtherTypes;

use lru_time_cache::LruCache;

const BUF_NUM: usize = 65536;
const BUF_LEN: usize = 4096;
const BATCH_SIZE: usize = 64;
const LOCAL_ARP_TTL: Duration = Duration::from_secs(300);

struct XDPWorker<'a> {
    core: usize,

    rx: SocketRx<'a, BufCustom>,
    tx: SocketTx<'a, BufCustom>,
    cq: UmemCompletionQueue<'a, BufCustom>,
    fq: UmemFillQueue<'a, BufCustom>,

    buf_pool: Arc<Mutex<BufPoolVec<BufMmap<'a, BufCustom>, BufCustom>>>,
    lb: LB,
    arp_cache: Arp,
    local_arp_cache: LruCache<Ipv4Addr, MacAddr>,
    default_gw_mac: MacAddr,
}

#[derive(Default, Copy, Clone)]
struct BufCustom {}

fn load_bpf(
    interface: &interface::Interface,
    bpf_program_path: &Path,
    xdp_flags: libbpf::XdpFlags,
    progsec: &str,
    map_name: &str,
) -> Result<(), rebpf_error::Error> {
    let (bpf_object, _bpf_fd) = libbpf::bpf_prog_load(bpf_program_path, libbpf::BpfProgType::XDP)?;
    let bpf_prog = libbpf::bpf_object__find_program_by_title(&bpf_object, progsec)?;
    let bpf_fd = libbpf::bpf_program__fd(&bpf_prog)?;

    libbpf::bpf_set_link_xdp_fd(&interface, Some(&bpf_fd), xdp_flags)?;
    let info = libbpf::bpf_obj_get_info_by_fd(&bpf_fd)?;
    info!(
        "Success Loading\n XDP prog name: {}, id {} on device: {}",
        info.name()?,
        info.id(),
        interface.ifindex()
    );

    let _bpf_map = libbpf::bpf_object__find_map_by_name(&bpf_object, map_name)?;

    Ok(())
}

fn unload_bpf(
    interface: &interface::Interface,
    xdp_flags: libbpf::XdpFlags,
) -> Result<(), rebpf_error::Error> {
    libbpf::bpf_set_link_xdp_fd(&interface, None, xdp_flags)?;
    info!("Success Unloading.");

    Ok(())
}

pub fn setup_and_run(
    lb: &mut LB,
    bpf_program_path: &str,
    progsec: &str,
    xsks_map_name: &str,
    stats_sender: Sender<StatsMssg>,
) -> Result<(), rebpf_error::Error> {
    let bpf_program = Path::new(&bpf_program_path);
    let interface = interface::get_interface(lb.iface.name.as_str())?;
    let xdp_flags = libbpf::XdpFlags::UPDATE_IF_NOEXIST | libbpf::XdpFlags::DRV_MODE;
    match load_bpf(&interface, bpf_program, xdp_flags, progsec, xsks_map_name) {
        Ok(_) => {}
        Err(e) => {
            warn!(
                "Unable to load BPF/XDP program, retrying in SKB Mode: {}",
                e
            );
            let xdp_flags = libbpf::XdpFlags::UPDATE_IF_NOEXIST | libbpf::XdpFlags::SKB_MODE;
            load_bpf(&interface, bpf_program, xdp_flags, progsec, xsks_map_name)?;
        }
    }

    let options = MmapAreaOptions { huge_tlb: false };
    let r = MmapArea::new(BUF_NUM, BUF_LEN, options);
    let (area, mut bufs) = match r {
        Ok((area, bufs)) => (area, bufs),
        Err(err) => panic!("Unable to create mmap for XDP load balancing: {:?}", err),
    };

    // Add all the Bufs to the global Buf pool
    let mut bp: BufPoolVec<BufMmap<BufCustom>, BufCustom> = BufPoolVec::new(bufs.len());
    let len = bufs.len();
    let r = bp.put(&mut bufs, len);
    assert!(r == len);

    // Wrap the BufPool in an Arc and Mutex (to share between worker threads)
    let bp = Arc::new(Mutex::new(bp));

    // setup and start global arp cache
    let mut arp_cache = Arp::new(lb.iface.clone(), lb.listen_ip).unwrap();
    arp_cache.clone().start();

    // should be populated by the time we get here
    let default_gw_mac = arp_cache.get_default_mac().unwrap();

    // should be a worker per core and no more
    for worker in 0..lb.workers {
        //
        // Create the AF_XDP umem and sockets for each worker
        //
        let r = Umem::new(
            area.clone(),
            XSK_RING_CONS__DEFAULT_NUM_DESCS,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
        );
        let (umem1, umem1cq, mut umem1fq) = match r {
            Ok(umem) => umem,
            Err(err) => panic!("Unable to create umem for XDP load balancing: {:?}", err),
        };

        let mut sock_opts = SocketOptions::default();
        sock_opts.copy_mode = true;

        let r = Socket::new(
            umem1.clone(),
            lb.iface.name.as_str(),
            worker,
            XSK_RING_CONS__DEFAULT_NUM_DESCS,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
            sock_opts,
        );
        let (_skt1, skt1rx, skt1tx) = match r {
            Ok(skt) => skt,
            Err(err) => {
                error!(
                    "Skipping Worker {:?}. Unable to create XSK for XDP load balancing: {:?}",
                    worker, err
                );
                continue;
            }
        };

        let mut worker = XDPWorker {
            core: worker as usize,

            rx: skt1rx,
            tx: skt1tx,
            cq: umem1cq,
            fq: umem1fq,

            buf_pool: bp.clone(),
            lb: lb.clone(),
            arp_cache: arp_cache.clone(),
            local_arp_cache: LruCache::<Ipv4Addr, MacAddr>::with_expiry_duration(LOCAL_ARP_TTL),
            default_gw_mac,
        };

        // spawn worker (native) threads
        let stats_sender = stats_sender.clone();
        thread::spawn(move || {
            worker.run(stats_sender);
        });
    }

    Ok(())
}

fn forward(
    tx: &mut SocketTx<BufCustom>,
    bufs: &mut ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping>,
    batch_size: usize,
) -> Result<usize, ()> {
    if bufs.is_empty() {
        return Ok(0);
    }

    let r = tx.try_send(bufs, batch_size);
    match r {
        Ok(n) => Ok(n),
        Err(e) => {
            error!("Unable to forward packets via AF_XDP socket: {:?}", e);
            Ok(0)
        }
    }
}

impl XDPWorker<'_> {
    pub fn run(&mut self, stats_sender: Sender<StatsMssg>) {
        let mut v: ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping> = ArrayDeque::new();
        let custom = BufCustom {};
        let mut fq_deficit = 0;

        let core = core_affinity::CoreId { id: self.core };
        core_affinity::set_for_current(core);

        const START_BUFS: usize = 8192;

        let mut bufs = Vec::with_capacity(START_BUFS);

        let r = self.buf_pool.lock().unwrap().get(&mut bufs, START_BUFS);
        if r != START_BUFS {
            println!(
                "Failed to get initial bufs. Wanted {} got {}",
                START_BUFS, r
            );
        }

        // Fill the worker Umem
        let r = self.fq.fill(
            &mut bufs,
            min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, BUF_NUM),
        );
        match r {
            Ok(n) => {
                if n != min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, BUF_NUM) {
                    panic!(
                        "Initial fill of umem incomplete. Wanted {} got {}.",
                        BUF_NUM, n
                    );
                }
            }
            Err(err) => panic!("error: {:?}", err),
        }

        debug!("Starting XDP Loop");
        loop {
            //
            // Service completion queue
            //
            let r = self.cq.service(&mut bufs, BATCH_SIZE);
            match r {
                Ok(_) => {}
                Err(err) => panic!("error: {:?}", err),
            }

            // Receive ring
            let r = self.rx.try_recv(&mut v, BATCH_SIZE, custom);
            match r {
                Ok(n) => {
                    if n > 0 {
                        debug!("XDP worker {:?} Received {:?} packets", self.core, n);
                        let r = self.process_packets(&mut v, &stats_sender);
                        match r {
                            Ok(_) => {}
                            Err(e) => error!("XDP: Problem processing packets: {:?}", e),
                        }
                        fq_deficit += n;
                    } else {
                        if self.fq.needs_wakeup() {
                            self.rx.wake();
                        }
                    }
                }
                Err(err) => {
                    error!("XDP: {:?}", err);
                }
            }

            // forward
            let r = forward(&mut self.tx, &mut v, BATCH_SIZE);
            match r {
                Ok(n) => {
                    if n > 0 {
                        debug!("XDP Sent {:?} packets", n)
                    };
                }
                Err(err) => error!("{:?}", err),
            }

            //
            // Fill buffers if required
            //
            if fq_deficit > 0 {
                let r = self.fq.fill(&mut bufs, fq_deficit);
                match r {
                    Ok(n) => {
                        fq_deficit -= n;
                    }
                    Err(err) => panic!("error: {:?}", err),
                }
            }
        }
    }

    fn process_packets(
        &mut self,
        bufs: &mut ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping>,
        stats_sender: &Sender<StatsMssg>,
    ) -> Result<(), ()> {
        let mut stats = StatsMssg {
            frontend: Some(self.lb.name.clone()),
            backend: self.lb.backend.name.clone(),
            connections: 0,
            bytes_tx: 0,
            bytes_rx: 0,
            servers: None,
        };

        for buf in bufs {
            let mut ethernet = MutableEthernetPacket::new(buf.get_data_mut()).unwrap();

            let mut ip_header = MutableIpv4Packet::new(ethernet.payload_mut()).unwrap();
            match MutableTcpPacket::new(ip_header.payload_mut()) {
                Some(tcp_header) => {
                    if tcp_header.get_destination() == self.lb.listen_port {
                        if let Some(processed_packet) =
                            self.lb
                                .client_handler(&mut ip_header, true)
                        {
                            // update stats
                            stats.connections += &processed_packet.pkt_stats.connections;
                            stats.bytes_rx += &processed_packet.pkt_stats.bytes_rx;
                            stats.bytes_tx += &processed_packet.pkt_stats.bytes_tx;

                            // set the appropriate ethernet destination on the mutated packet
                            let ip = processed_packet.ip_header.get_destination();
                            ethernet.set_destination(self.get_mac_addr(ip));
                            ethernet.set_source(self.arp_cache.local_mac);
                            ethernet.set_ethertype(EtherTypes::Ipv4);
                        };
                    } else if !self.lb.dsr {
                        // only handling server repsonses if not using dsr
                        let guard = self.lb.port_mapper.read().unwrap();
                        let client_addr = guard.get(&tcp_header.get_destination());
                        match client_addr {
                            Some(client_addr) => {
                                // drop the lock!
                                let cli_socket = &SocketAddr::new(client_addr.ip, client_addr.port);
                                std::mem::drop(guard);
                                // if true the client socketaddr is in portmapper and the connection/response from backend server is relevant
                                if let Some(processed_packet) = self.lb.server_response_handler(
                                    &mut ip_header,
                                    cli_socket,
                                    true,
                                ) {
                                    // update stats
                                    stats.connections += &processed_packet.pkt_stats.connections;
                                    stats.bytes_rx += &processed_packet.pkt_stats.bytes_rx;
                                    stats.bytes_tx += &processed_packet.pkt_stats.bytes_tx;

                                    // set the appropriate ethernet destination on the mutated packet
                                    let ip = processed_packet.ip_header.get_destination();
                                    ethernet.set_destination(self.get_mac_addr(ip));
                                    ethernet.set_source(self.arp_cache.local_mac);
                                    ethernet.set_ethertype(EtherTypes::Ipv4);
                                };
                            }
                            None => {}
                        }
                    }
                }
                None => {}
            }
        }

        // send the counters we've gathered for this bundle of packets
        match stats_sender.send(stats) {
            Ok(_) => {}
            Err(e) => error!("Error sending stats message on channel: {}", e),
        }
        Ok(())
    }

    // if the target ip is not on this LAN return default GW mac address.
    // if it is, try to get the mac addr from this core's/worker's local arp cache first
    // then try global arp cache and update local cache if found
    // otherwise fall back to sending to default GW
    fn get_mac_addr(&mut self, ip: Ipv4Addr) -> MacAddr {
        if self.arp_cache.get_network().contains(ip) {
            if let Some(mac_addr) = self.local_arp_cache.get(&ip) {
                return *mac_addr;
            }
            debug!("Local arp cache miss on IP {}", ip);
            if let Some(mac_addr) = self.arp_cache.get_mac(ip) {
                self.local_arp_cache.insert(ip, mac_addr);
                return mac_addr;
            } else {
                return self.default_gw_mac;
            }
        } else {
            return self.default_gw_mac;
        }
    }
}
