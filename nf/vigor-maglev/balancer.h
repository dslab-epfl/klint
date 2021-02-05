#pragma once

#include "state.h"

struct ld_balancer
{
    struct State *state;
    uint64_t flow_expiration_time;
    uint64_t backend_expiration_time;
};

struct ld_balancer *ld_balancer_alloc(size_t flow_capacity,
                                      size_t backend_capacity,
                                      size_t cht_height,
                                      uint64_t backend_expiration_time,
                                      uint64_t flow_expiration_time);
bool lb_get_backend(struct ld_balancer *balancer,
                                 struct lb_flow *flow,
                                 uint64_t now,
                                 uint16_t wan_device,
                                 struct lb_backend** out_backend);
void lb_process_heartbeat(struct ld_balancer *balancer,
                          struct lb_flow *flow,
                          uint16_t nic, uint64_t now);
