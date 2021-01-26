// This header is intended to be included *once*. It includes non-static declarations.

#include "net/skeleton.h"

#include "compat/uapi/linux/bpf.h"

#ifndef XDP_MAIN_FUNC
#error Please define XDP_MAIN_FUNC to the name of the main XDP function
#endif

int XDP_MAIN_FUNC(struct xdp_md* ctx);

void nf_handle(struct net_packet* packet)
{
#ifdef XDP_SKELETON_RESTRICT
	struct net_ether_header* ether_header;
	struct net_ipv4_header* ipv4_header;
	if (!net_get_ether_header(packet, &ether_header) || !net_get_ipv4_header(ether_header, &ipv4_header) || ipv4_header->next_proto_id != 6) {
		return;
	}
#endif

	struct xdp_md ctx = {
		.data = (uintptr_t) packet->data,
		.data_end = (uintptr_t) packet->data + packet->length,
		.ingress_ifindex = packet->device,
		._adjust_used = false
	};

	int result = XDP_MAIN_FUNC(&ctx);

	packet->data = (void*) ctx.data;
	packet->length = (ctx.data_end - ctx.data);

	if (result == XDP_TX) {
		net_transmit(packet, packet->device, UPDATE_ETHER_ADDRS);
	} else if (result == XDP_PASS) {
		// Do nothing, packet is supposed to go through but we don't have that notion
	} else if (result == XDP_DROP || result == XDP_ABORTED) {
		// Do nothing.
	} else if (result == XDP_REDIRECT) {
//TODO:		net_transmit(packet, (uint16_t) result, UPDATE_ETHER_ADDRS);
	}
}
