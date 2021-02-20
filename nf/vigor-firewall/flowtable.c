#include "flowtable.h"

#include "os/memory.h"
#include "structs/pool.h"
#include "structs/map.h"


struct flowtable
{
	struct flow* flows;
	struct os_map* flow_indexes;
	struct os_pool* port_allocator;
	uint64_t expiration_time;
};


struct flowtable* flowtable_init(time_t expiration_time, size_t max_flows)
{
	struct os_map* flow_indexes = os_map_alloc(sizeof(struct flow), max_flows); // TODO: 2*max_flows because it's only a small amount of additional space for a lot more tput when near full
	struct os_pool* port_allocator = os_pool_alloc(max_flows, expiration_time);
	struct flowtable* table = os_memory_alloc(1, sizeof(struct flowtable));
	table->flows = os_memory_alloc(max_flows, sizeof(struct flow));
	table->flow_indexes = flow_indexes;
	table->port_allocator = port_allocator;
	table->expiration_time = expiration_time;
	return table;
}

void flowtable_learn_internal(struct flowtable* table, time_t time, struct flow* flow)
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

bool flowtable_has_external(struct flowtable* table, time_t time, struct flow* flow)
{
	size_t index;
	time_t flow_time;
	if (os_map_get(table->flow_indexes, flow, &index) && os_pool_used(table->port_allocator, index, &flow_time) && time - table->expiration_time <= flow_time) {
		os_pool_refresh(table->port_allocator, time, index);
		return true;
	}

	return false;
}
