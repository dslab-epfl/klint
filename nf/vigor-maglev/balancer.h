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
	struct map* flow_to_flow_id;
	struct flow* flow_heap;
	struct index_pool* flow_chain;
	size_t* flow_id_to_backend_id;
	struct map* ip_to_backend_id;
	uint32_t* backend_ips;
	struct backend* backends;
	struct index_pool* active_backends;
	struct cht* cht;
};


static inline struct balancer *balancer_alloc(size_t flow_capacity, time_t flow_expiration_time, size_t backend_capacity, time_t backend_expiration_time, size_t cht_height)
{
	struct balancer *balancer = os_memory_alloc(1, sizeof(struct balancer));
	balancer->flow_to_flow_id = map_alloc(sizeof(struct flow), flow_capacity);
	balancer->flow_heap = os_memory_alloc(flow_capacity, sizeof(struct flow));
	balancer->flow_chain = index_pool_alloc(flow_capacity, flow_expiration_time);
	balancer->flow_id_to_backend_id = os_memory_alloc(flow_capacity, sizeof(size_t));
	balancer->ip_to_backend_id = map_alloc(sizeof(uint32_t), backend_capacity);
	balancer->backend_ips = os_memory_alloc(backend_capacity, sizeof(uint32_t));
	balancer->backends = os_memory_alloc(backend_capacity, sizeof(struct backend));
	balancer->active_backends = index_pool_alloc(backend_capacity, backend_expiration_time);
	balancer->cht = cht_alloc(cht_height, backend_capacity);
	return balancer;
}

static inline bool balancer_get_backend(struct balancer* balancer, struct flow* flow, time_t now, struct backend** out_backend)
{
	size_t flow_index;
	size_t backend_index;

	if (map_get(balancer->flow_to_flow_id, flow, &flow_index)) {
		backend_index = balancer->flow_id_to_backend_id[flow_index];
		if (index_pool_used(balancer->active_backends, now, backend_index)) {
			index_pool_refresh(balancer->flow_chain, now, flow_index);
			*out_backend = &(balancer->backends[backend_index]);
			return true;
		} else {
			map_remove(balancer->flow_to_flow_id, &(balancer->flow_heap[flow_index]));
			index_pool_return(balancer->flow_chain, flow_index);
			return balancer_get_backend(balancer, flow, now, out_backend);
		}
	}

	if (!cht_find_preferred_available_backend(balancer->cht, (void*)flow, sizeof(struct flow), balancer->active_backends, &backend_index, now)) {
		return false;
	}

	bool was_used;
	if (index_pool_borrow(balancer->flow_chain, now, &flow_index, &was_used)) {
		if (was_used) {
			map_remove(balancer->flow_to_flow_id, &(balancer->flow_heap[flow_index]));
		}
		balancer->flow_heap[flow_index] = *flow;
		balancer->flow_id_to_backend_id[flow_index] = backend_index;
		map_set(balancer->flow_to_flow_id, &(balancer->flow_heap[flow_index]), flow_index);
	} // Doesn't matter if we can't insert

	*out_backend = &(balancer->backends[backend_index]);
	return true;
}

static inline void balancer_process_heartbeat(struct balancer* balancer, struct flow* flow, device_t device, time_t now)
{
	size_t index;
	if (map_get(balancer->ip_to_backend_id, &flow->src_ip, &index)) {
		index_pool_refresh(balancer->active_backends, now, index);
	} else {
		bool was_used;
		if (index_pool_borrow(balancer->active_backends, now, &index, &was_used)) {
			if (was_used) {
				map_remove(balancer->ip_to_backend_id, &(balancer->backend_ips[index]));
			}
			struct backend *new_backend = &(balancer->backends[index]);
			new_backend->ip = flow->src_ip;
			new_backend->device = device;
			balancer->backend_ips[index] = flow->src_ip;
			map_set(balancer->ip_to_backend_id, &(balancer->backend_ips[index]), index);
		}
		// Otherwise ignore this backend, we are full.
	}
}
