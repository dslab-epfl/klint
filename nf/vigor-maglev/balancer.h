#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "net/packet.h"
#include "os/clock.h"
#include "os/memory.h"
#include "structs/map.h"
#include "structs/pool.h"
#include "structs/cht.h"


struct lb_backend {
  uint32_t ip;
  uint16_t nic;
  uint8_t _padding[2];
};

struct lb_flow {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
  uint8_t _padding[3];
};


struct State {
  struct os_map* flow_to_flow_id;
  struct lb_flow* flow_heap;
  struct os_pool* flow_chain;
  size_t* flow_id_to_backend_id;
  struct os_map* ip_to_backend_id;
  uint32_t* backend_ips;
  struct lb_backend* backends;
  struct os_pool* active_backends;
  struct cht* cht;
  size_t flow_capacity;
};

static inline struct State *state_alloc(size_t backend_capacity, size_t flow_capacity, size_t cht_height, time_t flow_expiration_time, time_t backend_expiration_time)
{
    // Allocate all data structures
    struct State *state = os_memory_alloc(1, sizeof(struct State));
    state->flow_to_flow_id = os_map_alloc(sizeof(struct lb_flow), flow_capacity);
    state->flow_heap = os_memory_alloc(flow_capacity, sizeof(struct lb_flow));
    state->flow_chain = os_pool_alloc(flow_capacity, flow_expiration_time);
    state->flow_id_to_backend_id = os_memory_alloc(flow_capacity, sizeof(size_t));
    state->ip_to_backend_id = os_map_alloc(sizeof(uint32_t), backend_capacity);
    state->backend_ips = os_memory_alloc(backend_capacity, sizeof(uint32_t));
    state->backends = os_memory_alloc(backend_capacity, sizeof(struct lb_backend));
    state->active_backends = os_pool_alloc(backend_capacity, backend_expiration_time);
    state->cht = cht_alloc(cht_height, backend_capacity);
    state->flow_capacity = flow_capacity;
    return state;
}


struct ld_balancer
{
    struct State *state;
    time_t flow_expiration_time;
    time_t backend_expiration_time;
};

static inline struct ld_balancer *ld_balancer_alloc(size_t flow_capacity,
                                      size_t backend_capacity,
                                      size_t cht_height,
                                      time_t backend_expiration_time,
                                      time_t flow_expiration_time)
{
    struct ld_balancer *balancer = os_memory_alloc(1, sizeof(struct ld_balancer));
    balancer->flow_expiration_time = flow_expiration_time;
    balancer->backend_expiration_time = backend_expiration_time;
    balancer->state = state_alloc(backend_capacity, flow_capacity, cht_height, flow_expiration_time, backend_expiration_time);
    return balancer;
}

static inline bool lb_get_backend(struct ld_balancer *balancer,
                                 struct lb_flow *flow,
                                 time_t now,
                                 device_t wan_device,
                                 struct lb_backend** out_backend)
{
    size_t flow_index;
    if (os_map_get(balancer->state->flow_to_flow_id, flow, &flow_index))
    {
        size_t backend_index = balancer->state->flow_id_to_backend_id[flow_index];
        if (os_pool_contains(balancer->state->active_backends, now, backend_index))
        {
            os_pool_refresh(balancer->state->flow_chain, now, flow_index);
            *out_backend = &balancer->state->backends[backend_index];
            return true;
        }
        else
        {
            os_map_remove(balancer->state->flow_to_flow_id, &balancer->state->flow_heap[flow_index]);
            os_pool_return(balancer->state->flow_chain, flow_index);
            return lb_get_backend(balancer, flow, now, wan_device, out_backend);
        }
    }
        size_t backend_index = 0;
        bool found = cht_find_preferred_available_backend(
            balancer->state->cht, (void*)flow, sizeof(struct lb_flow),
            balancer->state->active_backends, &backend_index, now);
        if (found)
        {
            size_t index;
            bool was_used;
            if (os_pool_borrow(balancer->state->flow_chain, now, &index, &was_used))
            {
            	if (was_used) {
	                os_map_remove(balancer->state->flow_to_flow_id, &balancer->state->flow_heap[index]);
	        }

                *flow = balancer->state->flow_heap[flow_index];
                balancer->state->flow_id_to_backend_id[flow_index] = backend_index;
                os_map_set(balancer->state->flow_to_flow_id, &balancer->state->flow_heap[flow_index], flow_index);
            } // Doesn't matter if we can't insert
            *out_backend = &balancer->state->backends[backend_index];
            return true;
        }
        return false;
}

static inline void lb_process_heartbeat(struct ld_balancer *balancer,
                          struct lb_flow *flow,
                          device_t nic,
                          time_t now)
{
    size_t backend_index;
    if (os_map_get(balancer->state->ip_to_backend_id, &flow->src_ip, &backend_index))
    {
        os_pool_refresh(balancer->state->active_backends, now, backend_index);
    }
    else
    {
        size_t index;
        bool was_used;
        if (os_pool_borrow(balancer->state->active_backends, now, &index, &was_used))
        {
            if (was_used) {
	            os_map_remove(balancer->state->ip_to_backend_id, &(balancer->state->backend_ips[index]));
	    }

            struct lb_backend *new_backend = &balancer->state->backends[backend_index];
            new_backend->ip = flow->src_ip;
            new_backend->nic = nic;

            balancer->state->backend_ips[backend_index] = flow->src_ip;
            os_map_set(balancer->state->ip_to_backend_id, &(balancer->state->backend_ips[backend_index]), backend_index);
        }
        // Otherwise ignore this backend, we are full.
    }
}
