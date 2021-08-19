// Implements Polycube in terms of XDP.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>


struct pkt_metadata {
	uint16_t in_port;
};

#define CTXTYPE xdp_md

enum {
//	RX_OK,
//	RX_REDIRECT,
	RX_DROP,
//	RX_RECIRCULATE,
//	RX_ERROR,
};

// Nothing
#define pcn_log(...)

static inline int pcn_pkt_redirect(struct xdp_md* pkt, struct pkt_metadata* md, uint32_t out_port)
{
	(void) pkt;
	(void) md;

	return (int) out_port;
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


// Polycube NFs implement this, it returns one of the RX_* values above and may call pcn_pkt_redirect or pcn_pkt_controller
static int handle_rx(struct xdp_md* ctx, struct pkt_metadata* md);

SEC("xdp")
int xdp_prog_polycube(struct xdp_md* ctx)
{
	struct pkt_metadata md = {
		.in_port = ctx->ingress_ifindex
	};

	int rx_result = handle_rx(ctx, &md);

	if (pcn_pkt_controller_flood) {
		return XDP_TX; // not great but oh well #ResearchCode
	} else if (rx_result == RX_DROP) {
		return XDP_DROP;
	} else {
		return XDP_TX;
	}
}
