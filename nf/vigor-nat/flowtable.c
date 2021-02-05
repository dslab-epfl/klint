//#include <stdio.h>
#include "flowtable.h"

#include "os/memory.h"
#include "structs/map.h"
#include "structs/pool.h"


struct flowtable
{
	struct flow* flows;
	struct os_map* flow_indexes;
	struct os_pool* port_allocator;
	uint64_t expiration_time;
	uint64_t max_flows;
	uint16_t start_port;
	uint8_t _padding[6];
};


struct flowtable* flowtable_alloc(uint16_t start_port, uint64_t expiration_time, uint64_t max_flows)
{
	struct os_map* flow_indexes = os_map_alloc(sizeof(struct flow), max_flows); // TODO: 2*max_flows because it's only a small amount of additional space for a lot more tput when near full
	struct os_pool* port_allocator = os_pool_alloc(max_flows);
	struct flowtable* table = os_memory_alloc(1, sizeof(struct flowtable));
	table->flows = os_memory_alloc(max_flows, sizeof(struct flow));
	table->flow_indexes = flow_indexes;
	table->port_allocator = port_allocator;
	table->expiration_time = expiration_time;
	table->max_flows = max_flows;
	table->start_port = start_port;
	return table;
}

bool flowtable_get_internal(struct flowtable* table, uint64_t time, struct flow* flow, uint16_t* out_port)
{
	uint64_t index;
	if (os_map_get(table->flow_indexes, flow, (void*) &index)) {
		os_pool_refresh(table->port_allocator, time, index);
	} else {
		if (os_pool_expire(table->port_allocator, time - table->expiration_time, &index)) {
//printf("expired: %lu at %lu due to exp time %lu\n", (long unsigned) index, (long unsigned) time, (long unsigned) table->expiration_time);
			os_map_remove(table->flow_indexes, &(table->flows[index]));
		}

		if (!os_pool_borrow(table->port_allocator, time, &index)) {
//printf("oh noes\n");
			return false;
		}

//printf("borrowed: %lu   at time %lu\n", (long unsigned)index, (long unsigned)time);
		table->flows[index] = *flow;
		os_map_set(table->flow_indexes, &(table->flows[index]), (void*) index);
	}

	*out_port = table->start_port + index;
	return true;
}

bool flowtable_get_external(struct flowtable* table, uint64_t time, uint16_t port, struct flow* out_flow)
{
	uint64_t index = (uint16_t) (port - table->start_port);
	// Per its contract, we cannot call 'os_pool_used' with an out-of-range index
	// TODO fix its contract?
	if (index >= table->max_flows) {
//printf("wtf?\n");
		return false;
	}

	uint64_t flow_time = (uint64_t)-1;
	if (!os_pool_used(table->port_allocator, index, &flow_time) || time - table->expiration_time > flow_time) {
//printf("unused or bad; idx= %lu at time %lu due to exp time %lu and flow time %lu\n", (long unsigned) index, (long unsigned) time, (long unsigned) table->expiration_time, (long unsigned) flow_time);
		return false;
	}

	os_pool_refresh(table->port_allocator, time, index);
	*out_flow = table->flows[index];
	return true;
}
