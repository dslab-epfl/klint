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

struct ld_balancer
{
    time_t flow_expiration_time;
    time_t backend_expiration_time;
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


static inline struct ld_balancer *ld_balancer_alloc(size_t flow_capacity,
                                      size_t backend_capacity,
                                      size_t cht_height,
                                      time_t backend_expiration_time,
                                      time_t flow_expiration_time)
{
    struct ld_balancer *balancer = os_memory_alloc(1, sizeof(struct ld_balancer));
    balancer->flow_expiration_time = flow_expiration_time;
    balancer->backend_expiration_time = backend_expiration_time;
    balancer->flow_to_flow_id = os_map_alloc(sizeof(struct lb_flow), flow_capacity);
    balancer->flow_heap = os_memory_alloc(flow_capacity, sizeof(struct lb_flow));
    balancer->flow_chain = os_pool_alloc(flow_capacity, flow_expiration_time);
    balancer->flow_id_to_backend_id = os_memory_alloc(flow_capacity, sizeof(size_t));
    balancer->ip_to_backend_id = os_map_alloc(sizeof(uint32_t), backend_capacity);
    balancer->backend_ips = os_memory_alloc(backend_capacity, sizeof(uint32_t));
    balancer->backends = os_memory_alloc(backend_capacity, sizeof(struct lb_backend));
    balancer->active_backends = os_pool_alloc(backend_capacity, backend_expiration_time);
    balancer->cht = cht_alloc(cht_height, backend_capacity);
    balancer->flow_capacity = flow_capacity;
    return balancer;
}

static inline bool lb_get_backend(struct ld_balancer *balancer,
                                 struct lb_flow *flow,
                                 time_t now,
                                 device_t wan_device,
                                 struct lb_backend** out_backend)
{
    size_t flow_index;
    if (os_map_get(balancer->flow_to_flow_id, flow, &flow_index))
    {
        size_t backend_index = balancer->flow_id_to_backend_id[flow_index];
        if (os_pool_contains(balancer->active_backends, now, backend_index))
        {
            os_pool_refresh(balancer->flow_chain, now, flow_index);
            *out_backend = &balancer->backends[backend_index];
            return true;
        }
        else
        {
            os_map_remove(balancer->flow_to_flow_id, &balancer->flow_heap[flow_index]);
            os_pool_return(balancer->flow_chain, flow_index);
            return lb_get_backend(balancer, flow, now, wan_device, out_backend);
        }
    }
        size_t backend_index = 0;
        bool found = cht_find_preferred_available_backend(
            balancer->cht, (void*)flow, sizeof(struct lb_flow),
            balancer->active_backends, &backend_index, now);
        if (found)
        {
            size_t index;
            bool was_used;
            if (os_pool_borrow(balancer->flow_chain, now, &index, &was_used))
            {
            	if (was_used) {
	                os_map_remove(balancer->flow_to_flow_id, &balancer->flow_heap[index]);
	        }

                *flow = balancer->flow_heap[flow_index];
                balancer->flow_id_to_backend_id[flow_index] = backend_index;
                os_map_set(balancer->flow_to_flow_id, &balancer->flow_heap[flow_index], flow_index);
            } // Doesn't matter if we can't insert
            *out_backend = &balancer->backends[backend_index];
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
    if (os_map_get(balancer->ip_to_backend_id, &flow->src_ip, &backend_index))
    {
        os_pool_refresh(balancer->active_backends, now, backend_index);
    }
    else
    {
        size_t index;
        bool was_used;
        if (os_pool_borrow(balancer->active_backends, now, &index, &was_used))
        {
            if (was_used) {
	            os_map_remove(balancer->ip_to_backend_id, &(balancer->backend_ips[index]));
	    }

            struct lb_backend *new_backend = &balancer->backends[backend_index];
            new_backend->ip = flow->src_ip;
            new_backend->nic = nic;

            balancer->backend_ips[backend_index] = flow->src_ip;
            os_map_set(balancer->ip_to_backend_id, &(balancer->backend_ips[backend_index]), backend_index);
        }
        // Otherwise ignore this backend, we are full.
    }
}
