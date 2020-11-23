// This file was obtained from the hXDP project, commit 51c067f7aba732bf85842d00a768bfe71ba55434 of https://github.com/axbryd/hXDP-Artifacts
// It was originally named xdp_progs/xdp_fw_kern.c
// The original file is <TODO license?>
// It was modified in the following ways:
// - Inlined "xdp_fw_common.h" (same folder and commit)
// - Removed SEC(...) instructions, which are not desirable for native compilation
// - Renamed 'xdp_fw_prog' to 'xdp_main' for our skeleton code to work
// - Replaced the 'tx_port' map of type BPF_MAP_TYPE_DEVMAP by returning the port directly
// - Replaced the Linux headers with our equivalent ones.
// - Replaced non-standard C constructs with their standard equivalents, such as using u8* instead of void* for pointers used in arithmetic
// - Fixed C constructs that cause warnings, such as removing unused declarations
// - Added an initialization function for the maps
// No other changes were performed; comments are from the original authors.

#define KBUILD_MODNAME "foo"

#include "os/skeleton/nf.h"
#include "compat/bpf/map.h"
#include "compat/bpf/xdp.h"
#include "compat/linux/types.h"
#include "compat/linux/if_ether.h"
#include "compat/linux/inet.h"
#include "compat/linux/ip.h"
#include "compat/linux/udp.h"

#define A_PORT  6
#define B_PORT 7



struct flow_ctx_table_key {
	/*per-application */
	__u16 ip_proto;
	__u16 l4_src;
	__u16 l4_dst;
	__u32 ip_src;
	__u32 ip_dst;

};

struct flow_ctx_table_leaf {
	__u8 out_port;
	__u16 in_port;
//	flow_register_t flow_reg;
};


//#define DEBUG 1
#ifdef  DEBUG

#define bpf_debug(fmt, ...)						\
			({							\
				char ____fmt[] = fmt;				\
				bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
			})
#else
#define bpf_debug(...) { } while (0)
#endif

static inline void biflow(struct flow_ctx_table_key *flow_key){
	u32 swap;
	if (flow_key->ip_src > flow_key->ip_dst){
		swap = flow_key->ip_src;
		flow_key->ip_src = flow_key->ip_dst;
		flow_key->ip_dst = swap;
	}

	if (flow_key->l4_src  > flow_key->l4_dst){
		swap = flow_key->l4_src;
		flow_key->l4_src = flow_key->l4_dst;
		flow_key->l4_dst = swap;
	}

}

struct bpf_map_def flow_ctx_table = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct flow_ctx_table_key),
	.value_size = sizeof(struct flow_ctx_table_leaf),
	.max_entries = 1024,
};


int xdp_main(struct xdp_md *ctx)
{
	u8* data_end = (u8*)ctx->data_end;
	u8* data         = (u8*)ctx->data;
	
	struct flow_ctx_table_leaf new_flow = {0};
	struct flow_ctx_table_key flow_key  = {0};
	struct flow_ctx_table_leaf *flow_leaf;

	struct ethhdr *ethernet;
	struct iphdr        *ip;
	struct udphdr      *l4;

	int ingress_ifindex;
	uint64_t nh_off = 0;
	/*  remember, to see printk 
	 * sudo cat /sys/kernel/debug/tracing/trace_pipe
	 */
	bpf_debug("I'm in the pipeline\n");

{
	ethernet = (struct ethhdr*) data ;
	nh_off = sizeof(*ethernet);
	if (data  + nh_off  > data_end)
		goto EOP;
	
	
	ingress_ifindex = ctx->ingress_ifindex;
//	if (!ntohs(ethernet->h_proto))
//		goto EOP;
	
	bpf_debug("I'm eth\n");
	switch (ntohs(ethernet->h_proto)) {
		case ETH_P_IP:    goto ip;
		default:          goto EOP;
	}
}

ip: {
	bpf_debug("I'm ip\n");
	
	ip = (struct iphdr*) (data + nh_off);
	nh_off +=sizeof(*ip);
	if (data + nh_off  > data_end)
		goto EOP;

	switch (ip->protocol) {
		case IPPROTO_TCP: goto l4;
		case IPPROTO_UDP: goto l4;
		default:          goto EOP;
	}
}

l4: {
	bpf_debug("I'm l4\n");
	l4 = (struct udphdr*) (data + nh_off);
	nh_off +=sizeof(*l4);
	if (data + nh_off  > data_end)
		goto EOP;
}

	bpf_debug("extracting flow key ... \n");
	/* flow key */
	flow_key.ip_proto = ip->protocol;

	flow_key.ip_src = ip->saddr;
	flow_key.ip_dst = ip->daddr;
	flow_key.l4_src = l4->source;
	flow_key.l4_dst = l4->dest;

	biflow(&flow_key);
	



	if (ingress_ifindex == B_PORT){
		flow_leaf = bpf_map_lookup_elem(&flow_ctx_table, &flow_key);
			
		if (flow_leaf)
			return flow_leaf->out_port;
		else 
			return XDP_DROP;
	} else {
		flow_leaf = bpf_map_lookup_elem(&flow_ctx_table, &flow_key);
			
		if (!flow_leaf){
			new_flow.in_port = B_PORT;
			new_flow.out_port = A_PORT; //ctx->ingress_ifindex ;
			bpf_map_update_elem(&flow_ctx_table, &flow_key, &new_flow, BPF_ANY);
		}
		
		return B_PORT;
	}


EOP:
	return XDP_DROP;

}

char _license[] = "GPL";

bool nf_init(uint16_t devices_count)
{
	(void) devices_count;
	bpf_map_init(&flow_ctx_table);
	return true;
}
