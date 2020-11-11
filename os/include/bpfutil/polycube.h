// This header is intended to be included *once*. It includes non-static declarations.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/network.h"

#include "bpfutil/types.h"


struct pkt_metadata {
	uint16_t in_port;
};

#define CTXTYPE xdp_md

enum {
//	RX_OK,
	RX_REDIRECT,
	RX_DROP,
//	RX_RECIRCULATE,
//	RX_ERROR,
};


// Polycube NFs implement this, it returns one of the RX_* values above and may call pcn_pkt_redirect or pcn_pkt_controller
static int handle_rx(struct xdp_md* ctx, struct pkt_metadata* md);

static uint32_t pcn_pkt_redirect_port = 0;
static inline int pcn_pkt_redirect(struct xdp_md* pkt, struct pkt_metadata* md, uint32_t out_port)
{
	(void) pkt;
	(void) md;

	pcn_pkt_redirect_port = out_port;
	return RX_REDIRECT;
}

static bool pcn_pkt_controller_flood = false;
static inline int pcn_pkt_controller(struct xdp_md* pkt, struct pkt_metadata* md, uint16_t reason)
{
	(void) pkt;
	(void) md;

	if (reason == 1) // REASON_FLOODING in simplebridge
	{
		pcn_pkt_controller_flood = true;
	}

	return 0;
}


bool nf_init(uint16_t devices_count)
{
	(void) devices_count;
	return true;
}


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
	} else if (rx_result == RX_REDIRECT) {
		struct os_net_ether_header* ether_header = NULL;
		os_net_get_ether_header(packet, &ether_header);
		os_net_transmit(packet, (uint16_t) pcn_pkt_redirect_port, ether_header, NULL, NULL);
	}
}
