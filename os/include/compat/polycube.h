#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/memory.h"

#include "compat/uapi/linux/bpf.h"


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

extern bool pcn_pkt_controller_flood;
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
