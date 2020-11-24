// This header is intended to be included *once*. It includes non-static declarations.

#include "compat/bpf/helpers.h"

#include "os/network.h"


#define XDP_DROP -1
#define XDP_TX -2
#define XDP_PASS -3

int xdp_main(struct xdp_md* ctx);

void nf_handle(struct os_net_packet* packet)
{
	struct xdp_md ctx = {
		.data = (uintptr_t) packet->data,
		.data_end = (uintptr_t) packet->data + packet->length,
		.ingress_ifindex = packet->device
	};

	int result = xdp_main(&ctx);
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
