#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/time.h"
#include "os/memory.h"
#include "structs/cht.h"
#include "structs/index_pool.h"
#include "structs/map.h"


struct flow
{
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	uint8_t _padding[3];
};

struct balancer
{
	struct map* flow_indices;
	struct index_pool* flow_pool;
	struct flow* flow_heap;
	size_t* flow_backends; // TODO change backends to device_t
	struct index_pool* backend_pool;
	struct cht* cht;
};

static inline struct balancer* balancer_alloc(size_t flow_capacity, time_t flow_expiration_time, size_t backend_capacity, time_t backend_expiration_time, size_t cht_height)
{
	struct balancer* balancer = os_memory_alloc(1, sizeof(struct balancer));
	balancer->flow_indices = map_alloc(sizeof(struct flow), flow_capacity);
	balancer->flow_pool = index_pool_alloc(flow_capacity, flow_expiration_time);
	balancer->flow_heap = os_memory_alloc(flow_capacity, sizeof(struct flow));
	balancer->flow_backends = os_memory_alloc(flow_capacity, sizeof(size_t));
	balancer->backend_pool = index_pool_alloc(backend_capacity, backend_expiration_time);
	balancer->cht = cht_alloc(cht_height, backend_capacity);
	return balancer;
}

static inline bool balancer_get_backend(struct balancer* balancer, struct flow* flow, time_t time, size_t* out_backend)
{
	size_t flow_index;
	size_t backend;
	if (map_get(balancer->flow_indices, flow, &flow_index)) {
		// We know the backend; is it alive?
		backend = balancer->flow_backends[flow_index];
		if (index_pool_used(balancer->backend_pool, time, backend)) {
			// Yes -> use it
			index_pool_refresh(balancer->flow_pool, time, flow_index);
			*out_backend = backend;
			return true;
		} else {
			// No -> remove this stale mapping and keep going
			map_remove(balancer->flow_indices, &(balancer->flow_heap[flow_index]));
			index_pool_return(balancer->flow_pool, flow_index);
		}
	}
	// Get a backend from the CHT
	if (!cht_find_preferred_available_backend(balancer->cht, (void*) flow, sizeof(struct flow), balancer->backend_pool, &backend, time)) {
		// There are no backends :(
		return false;
	}
	// Insert the mapping if possible, but it's OK if we can't
	bool was_used;
	if (index_pool_borrow(balancer->flow_pool, time, &flow_index, &was_used)) {
		if (was_used) {
			map_remove(balancer->flow_indices, &(balancer->flow_heap[flow_index]));
		}

		balancer->flow_heap[flow_index] = *flow;
		map_set(balancer->flow_indices, &(balancer->flow_heap[flow_index]), flow_index);
	}
	// And return the backend
	*out_backend = backend;
	return true;
}

static inline void balancer_process_heartbeat(struct balancer* balancer, size_t backend, time_t time)
{
	index_pool_refresh(balancer->backend_pool, time, backend);
}
