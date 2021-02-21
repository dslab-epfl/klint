#pragma once

#include <stddef.h>
#include <stdint.h>

#include "structs/map.h"
#include "structs/pool.h"
#include "structs/cht.h"

#include "os/clock.h"
#include "os/memory.h"


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
