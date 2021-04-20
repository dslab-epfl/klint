#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "net/packet.h"
#include "os/clock.h"
#include "os/memory.h"
#include "structs/cht.h"
#include "structs/index_pool.h"
#include "structs/map.h"


struct backend {
	uint32_t ip;
	device_t device;
	uint8_t _padding[2];
};

struct flow {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	uint8_t _padding[3];
};

struct balancer {
	struct map* flow_indices;
	struct flow* flows;
	struct index_pool* flow_times;
	size_t* flow_indices_to_backend_indices;
	struct map* ips_to_backend_indices;
	uint32_t* backend_ips;
	struct backend* backends;
	struct index_pool* active_backends;
	struct cht* cht;
};


static inline struct balancer* balancer_alloc(size_t flow_capacity, time_t flow_expiration_time, size_t backend_capacity, time_t backend_expiration_time, size_t cht_height)
{
	struct balancer* balancer = os_memory_alloc(1, sizeof(struct balancer));
	balancer->flow_indices = map_alloc(sizeof(struct flow), flow_capacity);
	balancer->flows = os_memory_alloc(flow_capacity, sizeof(struct flow));
	balancer->flow_times = index_pool_alloc(flow_capacity, flow_expiration_time);
	balancer->flow_indices_to_backend_indices = os_memory_alloc(flow_capacity, sizeof(size_t));
	balancer->ips_to_backend_indices = map_alloc(sizeof(uint32_t), backend_capacity);
	balancer->backend_ips = os_memory_alloc(backend_capacity, sizeof(uint32_t));
	balancer->backends = os_memory_alloc(backend_capacity, sizeof(struct backend));
	balancer->active_backends = index_pool_alloc(backend_capacity, backend_expiration_time);
	balancer->cht = cht_alloc(cht_height, backend_capacity);
	return balancer;
}

static inline bool balancer_get_backend(struct balancer* balancer, struct flow* flow, time_t time, struct backend** out_backend)
{
	size_t flow_index;
	size_t backend_index;

	if (map_get(balancer->flow_indices, flow, &flow_index)) {
		backend_index = balancer->flow_indices_to_backend_indices[flow_index];
		if (index_pool_used(balancer->active_backends, time, backend_index)) {
			index_pool_refresh(balancer->flow_times, time, flow_index);
			*out_backend = &(balancer->backends[backend_index]);
			return true;
		}

		map_remove(balancer->flow_indices, &(balancer->flows[flow_index]));
		index_pool_return(balancer->flow_times, flow_index);
		return balancer_get_backend(balancer, flow, time, out_backend);
	}

	if (!cht_find_preferred_available_backend(balancer->cht, (void*) flow, sizeof(struct flow), balancer->active_backends, &backend_index, time)) {
		return false;
	}

	bool was_used;
	if (index_pool_borrow(balancer->flow_times, time, &flow_index, &was_used)) {
		if (was_used) {
			map_remove(balancer->flow_indices, &(balancer->flows[flow_index]));
		}
		balancer->flows[flow_index] = *flow;
		balancer->flow_indices_to_backend_indices[flow_index] = backend_index;
		map_set(balancer->flow_indices, &(balancer->flows[flow_index]), flow_index);
	} // Doesn't matter if we can't insert

	*out_backend = &(balancer->backends[backend_index]);
	return true;
}

static inline void balancer_process_heartbeat(struct balancer* balancer, uint32_t src_ip, device_t device, time_t time)
{
	size_t index;
	bool was_used;
	if (map_get(balancer->ips_to_backend_indices, &src_ip, &index)) {
		index_pool_refresh(balancer->active_backends, time, index);
	} else if (index_pool_borrow(balancer->active_backends, time, &index, &was_used)) {
		if (was_used) {
			map_remove(balancer->ips_to_backend_indices, &(balancer->backend_ips[index]));
		}

		balancer->backend_ips[index] = src_ip;
		map_set(balancer->ips_to_backend_indices, &(balancer->backend_ips[index]), index);

		balancer->backends[index].ip = src_ip;
		balancer->backends[index].device = device;
	}
	// Otherwise ignore this backend, we are full.
}
