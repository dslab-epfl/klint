#pragma once

#include <stddef.h>
#include <stdbool.h>

#include "state.h"

#include "net/packet.h"
#include "os/clock.h"


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
                                 device_t wan_device,
                                 struct lb_backend** out_backend);
void lb_process_heartbeat(struct ld_balancer *balancer,
                          struct lb_flow *flow,
                          device_t nic, time_t now);
