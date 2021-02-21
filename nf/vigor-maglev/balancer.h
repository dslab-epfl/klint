#pragma once

#include <stddef.h>
#include <stdbool.h>

#include "state.h"

#include "net/packet.h"
#include "os/clock.h"
#include "os/memory.h"


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
