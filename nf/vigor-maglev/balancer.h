#pragma once

#include "state.h"

struct ld_balancer
{
    struct State *state;
    time_t flow_expiration_time;
    time_t backend_expiration_time;
};

struct ld_balancer *ld_balancer_alloc(size_t flow_capacity,
                                      size_t backend_capacity,
                                      size_t cht_height,
                                      time_t backend_expiration_time,
                                      time_t flow_expiration_time);
bool lb_get_backend(struct ld_balancer *balancer,
                                 struct lb_flow *flow,
                                 time_t now,
                                 uint16_t wan_device,
                                 struct lb_backend** out_backend);
void lb_process_heartbit(struct ld_balancer *balancer,
                         struct lb_flow *flow,
                         uint8_t* mac_addr, uint16_t nic, time_t now);
