#include "flowtable.h"

#include "os/memory.h"
#include "structs/map.h"
#include "structs/pool.h"


struct flowtable
{
	struct flow* flows;
	struct os_map* flow_indexes;
	struct os_pool* port_allocator;
};


struct flowtable* flowtable_init(time_t expiration_time, size_t max_flows)
{
	struct os_map* flow_indexes = os_map_alloc(sizeof(struct flow), max_flows);
	struct os_pool* port_allocator = os_pool_alloc(max_flows, expiration_time);
	struct flowtable* table = os_memory_alloc(1, sizeof(struct flowtable));
	table->flows = os_memory_alloc(max_flows, sizeof(struct flow));
	table->flow_indexes = flow_indexes;
	table->port_allocator = port_allocator;
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
	if (os_map_get(table->flow_indexes, flow, &index) && os_pool_contains(table->port_allocator, time, index)) {
		os_pool_refresh(table->port_allocator, time, index);
		return true;
	}

	return false;
}
