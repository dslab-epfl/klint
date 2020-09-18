#include <stdlib.h>

#include "state.h"
#include "os/memory.h"

// bool lb_backend_id_condition(void *value, int index, void *state)
// {
//     struct ip_addr *v = value;
//     return 0 <= index && index < 32;
// }
// bool lb_flow_id_condition(void *value, int index, void *state)
// {
//     struct lb_flow *v = value;
//     return 0 <= index && index < 65536;
// }
// bool lb_backend_condition(void *value, int index, void *state)
// {
//     struct lb_backend *v = value;
//     return 0 <= v->nic && v->nic < 3 && v->nic != 2;
// }
// bool lb_flow_id2backend_id_cond(void *value, int index, void *state)
// {
//     uint32_t v = *(uint32_t *)value;
//     return (v < 32);
// }

// bool lb_flow_eq(void *a, void *b)
// {
//     struct lb_flow *id1 = (struct lb_flow *)a;
//     struct lb_flow *id2 = (struct lb_flow *)b;
//     return (id1->src_ip == id2->src_ip) && (id1->dst_ip == id2->dst_ip) && (id1->src_port == id2->src_port) && (id1->dst_port == id2->dst_port) && (id1->protocol == id2->protocol);
// }

// unsigned lb_flow_hash(void *obj)
// {
//     struct lb_flow *id = (struct lb_flow *)obj;
//     unsigned hash = 0;
//     hash = __builtin_ia32_crc32si(hash, id->src_ip);
//     hash = __builtin_ia32_crc32si(hash, id->dst_ip);
//     hash = __builtin_ia32_crc32si(hash, id->src_port);
//     hash = __builtin_ia32_crc32si(hash, id->dst_port);
//     hash = __builtin_ia32_crc32si(hash, id->protocol);
//     return hash;
// }

// void lb_flow_allocate(void *obj)
// {
//     struct lb_flow *id = (struct lb_flow *)obj;
//     id->src_ip = 0;
//     id->dst_ip = 0;
//     id->src_port = 0;
//     id->dst_port = 0;
//     id->protocol = 0;
// }

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
