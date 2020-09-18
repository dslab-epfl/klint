#include "os/skeleton/nf.h"

#include "os/clock.h"
#include "os/config.h"
#include "os/debug.h"
#include "os/network.h"

#include "ld_balancer.h"

struct ld_balancer *balancer;

bool nf_init(uint16_t devices_count)
{
    // TODO probably need to add some checks on the "values" returned from os_config_get_*, we'll see during symbex
    uint32_t flow_capacity = os_config_get_u32("flow capacity");
    uint32_t backend_capacity = os_config_get_u32("backend capacity");
    uint32_t cht_height = os_config_get_u32("cht height");
    time_t end_expiration_time = os_config_get_time("end expiration time");
    time_t flow_expiration_time = os_config_get_time("flow expiration time");

    balancer = ld_balancer_alloc(flow_capacity, backend_capacity, cht_height, end_expiration_time, flow_expiration_time);
    return balancer != NULL;
}

void nf_handle(struct os_net_packet *packet)
{
}
