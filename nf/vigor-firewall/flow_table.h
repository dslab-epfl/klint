#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/clock.h"
#include "os/memory.h"
#include "structs/map.h"
#include "structs/pool.h"


struct flow
{
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	uint8_t _padding[3];
};

struct flow_table
{
	struct flow* flows;
	struct os_map* flow_indexes;
	struct os_pool* port_allocator;
};


static inline struct flow_table* flow_table_alloc(time_t expiration_time, size_t max_flows)
{
	struct flow_table* table = os_memory_alloc(1, sizeof(struct flow_table));
	struct os_map* flow_indexes = os_map_alloc(sizeof(struct flow), max_flows);
	struct os_pool* port_allocator = os_pool_alloc(max_flows, expiration_time);
	table->flows = os_memory_alloc(max_flows, sizeof(struct flow));
	table->flow_indexes = flow_indexes;
	table->port_allocator = port_allocator;
	return table;
}

static inline void flow_table_learn_internal(struct flow_table* table, time_t time, struct flow* flow)
{
	size_t index;
	bool was_used;
	if (os_map_get(table->flow_indexes, flow, &index)) {
		os_pool_refresh(table->port_allocator, time, index);
	} else if (os_pool_borrow(table->port_allocator, time, &index, &was_used)) {
		if (was_used) {
			os_map_remove(table->flow_indexes, &(table->flows[index]));
		}

		table->flows[index] = *flow;
		os_map_set(table->flow_indexes, &(table->flows[index]), index);
	}
}

static inline bool flow_table_has_external(struct flow_table* table, time_t time, struct flow* flow)
{
	size_t index;
	if (os_map_get(table->flow_indexes, flow, &index) && os_pool_contains(table->port_allocator, time, index)) {
		os_pool_refresh(table->port_allocator, time, index);
		return true;
	}

	return false;
}
