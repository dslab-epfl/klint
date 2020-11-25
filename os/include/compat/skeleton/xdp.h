// This header is intended to be included *once*. It includes non-static declarations.

#include "os/skeleton/nf.h"

#include "compat/uapi/linux/bpf.h"

#ifndef XDP_MAIN_FUNC
#error Please define XDP_MAIN_FUNC to the name of the main XDP function
#endif

extern void* scratch_space;

int XDP_MAIN_FUNC(struct xdp_md* ctx);

void nf_handle(struct os_net_packet* packet)
{
	struct xdp_md ctx = {
		.data = (uintptr_t) packet->data,
		.data_end = (uintptr_t) packet->data + packet->length,
		.ingress_ifindex = packet->device,
		._adjust_scratch = scratch_space,
		._adjust_used = false
	};

	int result = XDP_MAIN_FUNC(&ctx);
	packet->data = (void*) ctx.data;
	packet->length = (ctx.data_end - ctx.data);
	if (result == XDP_TX) {
		os_net_transmit(packet, packet->device, (struct os_net_ether_header*) packet->data, 0, 0);
	} else if (result == XDP_PASS) {
		// Do nothing, packet is supposed to go through but we don't have that notion
	} else if (result == XDP_DROP) {
		// Do nothing.
	} else {
		os_net_transmit(packet, (uint16_t) result, (struct os_net_ether_header*) packet->data, 0, 0);
	}
}
