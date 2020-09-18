#ifndef _STATE_H_INCLUDED_
#define _STATE_H_INCLUDED_

#include <stdint.h>

#include "cht.h"
#include "structs.h"
#include "os/structs/map.h"
#include "os/structs/pool.h"

struct State {
  struct os_map* flow_to_flow_id;
  struct lb_flow* flow_heap;
  struct os_pool* flow_chain;
  uint32_t* flow_id_to_backend_id;
  struct os_map* ip_to_backend_id;
  struct ip_addr* backend_ips;
  struct lb_backend* backends;
  struct os_pool* active_backends;
  struct cht* cht;
  uint32_t flow_capacity;
};

struct State* state_alloc(uint32_t backend_capacity, uint32_t flow_capacity, uint32_t cht_height);

#endif//_STATE_H_INCLUDED_
