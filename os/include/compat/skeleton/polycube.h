// This header is intended to be included *once*. It includes non-static declarations.

#include "compat/polycube.h"

#include "net/tx.h"

// See compat/polycube.h
bool pcn_pkt_controller_flood = false;
// See compat/uapi/linux/bpf.h
uint64_t compat_bpf_time;

// Polycube NFs implement this, it returns one of the RX_* values above and may call pcn_pkt_redirect or pcn_pkt_controller
int handle_rx(struct xdp_md* ctx, struct pkt_metadata* md);

void nf_handle(struct net_packet* packet)
{
	compat_bpf_time = packet->time;
	struct xdp_md ctx = {
		.data = (uintptr_t) packet->data,
		.data_end = (uintptr_t) packet->data + packet->length
	};
	struct pkt_metadata md = {
		.in_port = packet->device
	};

	int rx_result = handle_rx(&ctx, &md);

	if (pcn_pkt_controller_flood) {
		net_flood(packet, 0);
	} else if (rx_result == RX_DROP) {
		// Do nothing
	} else {
		net_transmit(packet, (uint16_t) rx_result, UPDATE_ETHER_ADDRS);
	}
}
