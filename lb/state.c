#include <stdlib.h>

#include "state.h"
#include "os/memory.h"

struct State *state_alloc(uint32_t backend_capacity, uint32_t flow_capacity, uint32_t cht_height)
{
    struct State *state = os_memory_alloc(1, sizeof(struct State));
    state->flow_to_flow_id = os_map_alloc(sizeof(struct lb_flow), flow_capacity);
    state->flow_heap = os_memory_alloc(flow_capacity, sizeof(struct lb_flow));
    state->flow_chain = os_pool_alloc(flow_capacity);
    state->flow_id_to_backend_id = os_memory_alloc(flow_capacity, sizeof(uint32_t));
    state->ip_to_backend_id = os_map_alloc(sizeof(struct ip_addr), backend_capacity);
    state->backend_ips = os_memory_alloc(backend_capacity, sizeof(struct ip_addr));
    state->backends = os_memory_alloc(backend_capacity, sizeof(struct lb_backend));
    state->active_backends = os_pool_alloc(backend_capacity);
    state->cht = cht_alloc(cht_height, backend_capacity);
    state->flow_capacity = flow_capacity;

    // Check that all allocation were successful (don't need to check for os_memory_alloc)
    if (state->flow_to_flow_id == NULL || state->flow_chain == NULL || state->ip_to_backend_id == NULL || state->active_backends == NULL)
    {
        return NULL;
    }
    return state;
}
