#pragma once

#include <stdint.h>

#include "structs.h"
#include "os/structs/map.h"
#include "os/structs/pool.h"
#include "os/structs/cht.h"

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

struct State* state_alloc(size_t backend_capacity, size_t flow_capacity, size_t cht_height);
