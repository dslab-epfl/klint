// This header is intended to be included *once*. It includes non-static declarations.

#include "os/skeleton/nf.h"

#include "compat/uapi/linux/bpf.h"

#ifndef XDP_MAIN_FUNC
#error Please define XDP_MAIN_FUNC to the name of the main XDP function
#endif

int XDP_MAIN_FUNC(struct xdp_md* ctx);

void nf_handle(struct os_net_packet* packet)
{
#ifdef XDP_SKELETON_RESTRICT
	struct os_net_ether_header* ether_header;
	struct os_net_ipv4_header* ipv4_header;
	if (!os_net_get_ether_header(packet, &ether_header) || !os_net_get_ipv4_header(ether_header, &ipv4_header) || ipv4_header->next_proto_id != 6) {
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
		os_net_transmit(packet, packet->device, (struct os_net_ether_header*) packet->data, 0, 0);
	} else if (result == XDP_PASS) {
		// Do nothing, packet is supposed to go through but we don't have that notion
	} else if (result == XDP_DROP || result == XDP_ABORTED) {
		// Do nothing.
	} else if (result == XDP_REDIRECT) {
//TODO:		os_net_transmit(packet, (uint16_t) result, (struct os_net_ether_header*) packet->data, 0, 0);
	}
}
