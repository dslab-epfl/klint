// This header is intended to be included *once*. It includes non-static declarations.

#include "compat/polycube.h"

// See compat/polycube.h
bool pcn_pkt_controller_flood = false;

// Polycube NFs implement this, it returns one of the RX_* values above and may call pcn_pkt_redirect or pcn_pkt_controller
int handle_rx(struct xdp_md* ctx, struct pkt_metadata* md);

void nf_handle(struct os_net_packet* packet)
{
	struct xdp_md ctx = {
		.data = (uintptr_t) packet->data,
		.data_end = (uintptr_t) packet->data + packet->length
	};
	struct pkt_metadata md = {
		.in_port = packet->device
	};

	int rx_result = handle_rx(&ctx, &md);

	if (pcn_pkt_controller_flood) {
		os_net_flood(packet);
	} else if (rx_result == RX_DROP) {
		// Do nothing
	} else {
		os_net_transmit(packet, (uint16_t) rx_result, (struct os_net_ether_header*) packet->data, NULL, NULL);
	}
}
