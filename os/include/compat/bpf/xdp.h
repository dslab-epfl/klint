// This header is intended to be included *once*. It includes non-static declarations.

#include "compat/bpf/xdp_md.h"

#define XDP_DROP -1

int xdp_main(struct xdp_md* ctx);

void nf_handle(struct os_net_packet* packet)
{
	struct xdp_md ctx = {
		.data = (uintptr_t) packet->data,
		.data_end = (uintptr_t) packet->data + packet->length,
		.ingress_ifindex = packet->device
	};

	int result = xdp_main(&ctx);
	if (result != XDP_DROP) {
		os_net_transmit(packet, (uint16_t) result, (struct os_net_ether_header*) packet->data, 0, 0);
	}
}
