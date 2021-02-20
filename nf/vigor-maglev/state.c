#include "state.h"
#include "os/memory.h"

struct State *state_alloc(size_t backend_capacity, size_t flow_capacity, size_t cht_height, time_t flow_expiration_time, time_t backend_expiration_time)
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
