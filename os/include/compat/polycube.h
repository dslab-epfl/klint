// This header is intended to be included *once*. It includes non-static declarations.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/memory.h"
#include "os/network.h"
#include "os/structs/map2.h"

#include "compat/bpf/helpers.h"


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

struct bpfutil_table {
	void* value_holder; // silly hack, will work as long as bpf programs don't reuse results from previous gets
	struct os_map2* map;
};


static inline void bpfutil_table_update(struct bpfutil_table table, void* key, void* value)
{
	os_map2_set(table.map, key, value);
}

static inline void* bpfutil_table_lookup(struct bpfutil_table table, void* key)
{
	if (os_map2_get(table.map, key, table.value_holder)) {
		return table.value_holder;
	}
	return NULL;
}

static inline void bpfutil_table_delete(struct bpfutil_table table, void* key)
{
	os_map2_remove(table.map, key);
}

#define BPF_TABLE_hash(key_type, value_type, name, size) \
	name = (struct bpfutil_table) { .value_holder = os_memory_alloc(1, sizeof(value_type)), .map = os_map2_alloc(sizeof(key_type), sizeof(value_type), size) }

#define BPF_TABLE(type, key_type, value_type, name, size) BPF_TABLE_##type(key_type, value_type, name, size)


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
