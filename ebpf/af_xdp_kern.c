/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "./xdp-tutorial/common/parsing_helpers.h"

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

SEC("xdp_filter_3000")
int xdp_filter_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
    struct hdr_cursor nh = { .pos = data };
    struct iphdr *iph;
    struct tcphdr *tcph;
	int eth_type, ip_type;

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iph);
        if (ip_type == IPPROTO_TCP) {
		    if (parse_tcphdr(&nh, data_end, &tcph) < 0) {
			    return XDP_ABORTED;
            }
            if (bpf_ntohs(tcph->dest)==3000 ) {
                /* A set entry here means that the correspnding queue_id
                * has an active AF_XDP socket bound to it. */
                if (bpf_map_lookup_elem(&xsks_map, &index))
                    return bpf_redirect_map(&xsks_map, index, 0);
            }

            // catch ephemeral ports as well.  Comment this section out for
            // runnning in DSR mode 
            if (bpf_ntohs(tcph->dest)>=33768 ) {
                /* A set entry here means that the correspnding queue_id
                * has an active AF_XDP socket bound to it. */
                if (bpf_map_lookup_elem(&xsks_map, &index))
                    return bpf_redirect_map(&xsks_map, index, 0);
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
