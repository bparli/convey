use arraydeque::{ArrayDeque, Wrapping};
use rebpf::{error as rebpf_error, interface, libbpf};
use std::cmp::min;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use super::arp::{get_broadcast_addr, Arp};
use super::lb::LB;
use crate::stats::StatsMssg;
use afxdp::buf::Buf;
use afxdp::buf_mmap::BufMmap;
use afxdp::mmap_area::{MmapArea, MmapAreaOptions};
use afxdp::socket::{Socket, SocketOptions, SocketRx, SocketTx};
use afxdp::umem::{Umem, UmemCompletionQueue, UmemFillQueue};
use afxdp::PENDING_LEN;
use libbpf_sys::{XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS};
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

const BUF_NUM: usize = 65536;
const BUF_LEN: usize = 4096;
const BATCH_SIZE: usize = 64;

struct XDPState<'a> {
    cq: UmemCompletionQueue<'a, BufCustom>,
    fq: UmemFillQueue<'a, BufCustom>,
    rx: SocketRx<'a, BufCustom>,
    tx: SocketTx<'a, BufCustom>,
    fq_deficit: usize,
    mmap_bufs: Vec<BufMmap<'a, BufCustom>>,
}

pub struct XDP<'a> {
    state: XDPState<'a>,
    arp_cache: Arp,
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

pub fn setup(
    iface: NetworkInterface,
    listen_ip: Ipv4Addr,
    bpf_program_path: &str,
    progsec: &str,
    xsks_map_name: &str,
) -> Result<XDP<'static>, rebpf_error::Error> {
    let bpf_program = Path::new(&bpf_program_path);
    let interface = interface::get_interface(iface.name.as_str())?;
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
        iface.name.as_str(),
        0,
        XSK_RING_CONS__DEFAULT_NUM_DESCS,
        XSK_RING_PROD__DEFAULT_NUM_DESCS,
        sock_opts,
    );
    let (_skt1, skt1rx, skt1tx) = match r {
        Ok(skt) => skt,
        Err(err) => panic!("Unable to create XSK for XDP load balancing: {:?}", err),
    };

    // Fill the Umem
    let r = umem1fq.fill(
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

    let arp_cache = Arp::new(iface.clone(), listen_ip).unwrap();
    arp_cache.clone().start();

    Ok(XDP {
        state: XDPState {
            cq: umem1cq,
            fq: umem1fq,
            rx: skt1rx,
            tx: skt1tx,
            fq_deficit: 0,
            mmap_bufs: bufs,
        },
        arp_cache: arp_cache,
    })
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

impl<'a> XDP<'a> {
    pub fn run(&mut self, lb: &mut LB, stats_sender: Sender<StatsMssg>) {
        let mut v: ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping> = ArrayDeque::new();
        let custom = BufCustom {};

        debug!("Starting XDP Loop");
        loop {
            //
            // Service completion queue
            //
            let r = self.state.cq.service(&mut self.state.mmap_bufs, BATCH_SIZE);
            match r {
                Ok(n) => {}
                Err(err) => panic!("error: {:?}", err),
            }

            // Receive ring
            let r = self.state.rx.try_recv(&mut v, BATCH_SIZE, custom);
            match r {
                Ok(n) => {
                    if n > 0 {
                        debug!("XDP Received {:?} packets", n);
                        let r = self.process_packets(lb, &mut v, &stats_sender);
                        match r {
                            Ok(_) => {}
                            Err(e) => error!("XDP: Problem processing packets: {:?}", e),
                        }
                        self.state.fq_deficit += n;
                    } else {
                        if self.state.fq.needs_wakeup() {
                            self.state.rx.wake();
                        }
                    }
                }
                Err(err) => {
                    error!("XDP: {:?}", err);
                }
            }

            // forward
            let r = forward(&mut self.state.tx, &mut v, BATCH_SIZE);
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
            if self.state.fq_deficit > 0 {
                let r = self
                    .state
                    .fq
                    .fill(&mut self.state.mmap_bufs, self.state.fq_deficit);
                match r {
                    Ok(n) => {
                        self.state.fq_deficit -= n;
                    }
                    Err(err) => panic!("error: {:?}", err),
                }
            }
        }
    }

    fn process_packets(
        &mut self,
        lb: &mut LB,
        bufs: &mut ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping>,
        stats_sender: &Sender<StatsMssg>,
    ) -> Result<(), ()> {
        let mut stats = StatsMssg {
            frontend: Some(lb.name.clone()),
            backend: lb.backend.name.clone(),
            connections: 0,
            bytes_tx: 0,
            bytes_rx: 0,
            servers: None,
        };

        for buf in bufs {
            let mut ethernet = MutableEthernetPacket::new(buf.get_data_mut()).unwrap();

            let mut ip_header = MutableIpv4Packet::new(ethernet.payload_mut()).unwrap();
            match MutableTcpPacket::owned(ip_header.payload().to_owned()) {
                Some(mut tcp_header) => {
                    if tcp_header.get_destination() == lb.listen_port {
                        if let Some(processed_packet) =
                            lb.client_handler(&mut ip_header, &mut tcp_header, true)
                        {
                            // set the appropriate ethernet destination on the mutated packet
                            let target_mac: MacAddr;
                            if let Some(mac_addr) = self
                                .arp_cache
                                .get_mac(processed_packet.ip_header.get_destination())
                            {
                                target_mac = mac_addr;
                            } else {
                                target_mac = get_broadcast_addr();
                            }
                            stats.connections += &processed_packet.pkt_stats.connections;
                            stats.bytes_rx += &processed_packet.pkt_stats.bytes_rx;
                            stats.bytes_tx += &processed_packet.pkt_stats.bytes_tx;

                            ethernet.set_destination(target_mac);
                            // update stats
                        };
                    } else if !lb.dsr {
                        // only handling server repsonses if not using dsr
                        let guard = lb.port_mapper.read().unwrap();
                        let client_addr = guard.get(&tcp_header.get_destination());
                        match client_addr {
                            Some(client_addr) => {
                                // drop the lock!
                                let cli_socket = &SocketAddr::new(client_addr.ip, client_addr.port);
                                std::mem::drop(guard);
                                // if true the client socketaddr is in portmapper and the connection/response from backend server is relevant
                                if let Some(processed_packet) = lb.server_response_handler(
                                    &mut ip_header,
                                    &mut tcp_header,
                                    cli_socket,
                                    true,
                                ) {
                                    // set the appropriate ethernet destination on the mutated packet
                                    let target_mac: MacAddr;
                                    if let Some(mac_addr) = self
                                        .arp_cache
                                        .get_mac(processed_packet.ip_header.get_destination())
                                    {
                                        target_mac = mac_addr;
                                    } else {
                                        target_mac = get_broadcast_addr();
                                    }

                                    // update stats
                                    stats.connections += &processed_packet.pkt_stats.connections;
                                    stats.bytes_rx += &processed_packet.pkt_stats.bytes_rx;
                                    stats.bytes_tx += &processed_packet.pkt_stats.bytes_tx;

                                    ethernet.set_destination(target_mac);
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
}
