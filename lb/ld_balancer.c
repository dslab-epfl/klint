
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "ld_balancer.h"
#include "os/memory.h"

static int expire_items_single_map(struct os_pool *chain,
                                   void **vector,
                                   struct os_map *map,
                                   time_t time)
{
    int count = 0;
    size_t index;
    while (os_pool_expire(chain, time, &index))
    {
        void **key = &vector[index];
        os_map_remove(map, (void *)key);
        ++count;
    }
    return count;
}

static unsigned lb_flow_hash(struct lb_flow *obj)
{
    // We don't really care what's in there
    return obj->src_ip;
}

struct ld_balancer *ld_balancer_alloc(uint32_t flow_capacity,
                                      uint32_t backend_capacity,
                                      uint32_t cht_height,
                                      time_t backend_expiration_time,
                                      time_t flow_expiration_time)
{
    struct ld_balancer *balancer = os_memory_alloc(1, sizeof(struct ld_balancer));
    balancer->flow_expiration_time = flow_expiration_time;
    balancer->backend_expiration_time = backend_expiration_time;
    balancer->state = state_alloc(backend_capacity, flow_capacity, cht_height);
    // if (balancer->state == NULL)
    // {
    //     // Don't free anything, exiting.
    //     return NULL;
    // }
    return balancer;
}

struct lb_backend lb_get_backend(struct ld_balancer *balancer,
                                 struct lb_flow *flow,
                                 time_t now,
                                 uint16_t wan_device)
{
    size_t flow_index;
    struct lb_backend backend;
    if (!os_map_get(balancer->state->flow_to_flow_id, flow, (void **)&flow_index))
    {
        uint32_t backend_index = 0;
        uint32_t found = cht_find_preferred_available_backend(
            balancer->state->cht, (uint64_t)lb_flow_hash(flow),
            balancer->state->active_backends, &backend_index);
        if (found)
        {
            if (os_pool_borrow(balancer->state->flow_chain, now, &flow_index))
            {
                struct lb_flow *vec_flow = &balancer->state->flow_heap[flow_index];
                memcpy(vec_flow, flow, sizeof(struct lb_flow));

                uint32_t *vec_flow_id_to_backend_id = &balancer->state->flow_id_to_backend_id[flow_index];
                *vec_flow_id_to_backend_id = backend_index;

                os_map_set(balancer->state->flow_to_flow_id, vec_flow, (void *)flow_index);
            } // Doesn't matter if we can't insert
            struct lb_backend *vec_backend = &balancer->state->backends[backend_index];
            memcpy(&backend, vec_backend, sizeof(struct lb_backend));
        }
        else
        {
            // Drop
            backend.nic = wan_device; // The wan interface.
        }
    }
    else
    {
        uint32_t backend_index = balancer->state->flow_id_to_backend_id[flow_index];
        time_t out_time;
        if (!os_pool_used(balancer->state->active_backends, backend_index, &out_time))
        {
            struct lb_flow *flow_in_map_ptr = &balancer->state->flow_heap[flow_index];
            os_map_remove(balancer->state->flow_to_flow_id, flow_in_map_ptr);
            os_pool_return(balancer->state->flow_chain, flow_index);
            return lb_get_backend(balancer, flow, now, wan_device);
        }
        else
        {
            os_pool_refresh(balancer->state->flow_chain, now, flow_index);
            struct lb_backend *vec_backend = &balancer->state->backends[backend_index];
            memcpy(&backend, vec_backend, sizeof(struct lb_backend));
        }
    }
    return backend;
}

void lb_process_heartbit(struct ld_balancer *balancer,
                         struct lb_flow *flow,
                         struct ether_addr mac_addr, int nic,
                         time_t now)
{
    size_t backend_index;
    if (!os_map_get(balancer->state->ip_to_backend_id, &flow->src_ip, (void *)&backend_index))
    {
        if (os_pool_borrow(balancer->state->active_backends, now, &backend_index))
        {
            struct lb_backend *new_backend = &balancer->state->backends[backend_index];
            new_backend->ip = flow->src_ip;
            new_backend->mac = mac_addr;
            new_backend->nic = nic;

            struct ip_addr *ip = &balancer->state->backend_ips[backend_index];
            ip->addr = flow->src_ip;
            os_map_set(balancer->state->ip_to_backend_id, ip, (void *)backend_index);
        }
        // Otherwise ignore this backend, we are full.
    }
    else
    {
        os_pool_refresh(balancer->state->active_backends, now, backend_index);
    }
}

void lb_expire_flows(struct ld_balancer *balancer, time_t time)
{
    // Asserts from Vigor code removed
    uint64_t time_u = (uint64_t)time;
    time_t last_time = time_u - balancer->flow_expiration_time * 1000; // us to ns
    // expire_items_single_map(balancer->state->flow_chain,
    //                         (void **)balancer->state->flow_heap,
    //                         balancer->state->flow_to_flow_id, last_time);

    // Inlining expire_items_single_map because it sometimes causes a 
    // "memory might not be present" error on the call to os_map_remove
    size_t index;
    while (os_pool_expire(balancer->state->flow_chain, last_time, &index))
    {
        struct lb_flow *flow = &balancer->state->flow_heap[index];
        os_map_remove(balancer->state->flow_to_flow_id, flow);
    }
}

void lb_expire_backends(struct ld_balancer *balancer, time_t time)
{
    // Asserts from Vigor code removed
    uint64_t time_u = (uint64_t)time;
    time_t last_time = time_u - balancer->backend_expiration_time * 1000; // us to ns
    // expire_items_single_map(balancer->state->active_backends,
    //                         (void **)balancer->state->backend_ips,
    //                         balancer->state->ip_to_backend_id, last_time);

    // Inlining expire_items_single_map because it sometimes causes a 
    // "memory might not be present" error on the call to os_map_remove
    size_t index;
    while (os_pool_expire(balancer->state->active_backends, last_time, &index))
    {
        struct ip_addr *ip = &balancer->state->backend_ips[index];
        os_map_remove(balancer->state->ip_to_backend_id, ip);
    }
}
