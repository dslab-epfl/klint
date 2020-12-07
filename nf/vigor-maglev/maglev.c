#include <string.h>

#include "os/skeleton/nf.h"

#include "os/clock.h"
#include "os/config.h"
#include "os/debug.h"
#include "os/network.h"

#include "balancer.h"

struct ld_balancer *balancer;
uint16_t wan_device;

bool nf_init(uint16_t devices_count)
{
    wan_device = os_config_get_u16("wan device");
    if (wan_device >= devices_count)
    {
        return false;
    }

    size_t flow_capacity = os_config_get_u64("flow capacity");
    if (flow_capacity > SIZE_MAX / 16 - 2) {
    	return false;
    }
    size_t cht_height = os_config_get_u64("cht height");
    if (cht_height == 0 || cht_height >= MAX_CHT_HEIGHT) {
        return false;
    }
    size_t backend_capacity = os_config_get_u64("backend capacity");
    if (backend_capacity == 0 || backend_capacity >= cht_height || backend_capacity * cht_height >= UINT32_MAX || flow_capacity > SIZE_MAX / 16 - 2) {
        return false;
    }
    time_t backend_expiration_time = os_config_get_time("backend expiration time");
    time_t flow_expiration_time = os_config_get_time("flow expiration time");

    balancer = ld_balancer_alloc(flow_capacity, backend_capacity, cht_height, backend_expiration_time, flow_expiration_time);
    return balancer != NULL;
}

void nf_handle(struct os_net_packet *packet)
{
    struct os_net_ether_header *ether_header;
    struct os_net_ipv4_header *ipv4_header;
    struct os_net_tcpudp_header *tcpudp_header;
    if (!os_net_get_ether_header(packet, &ether_header) || !os_net_get_ipv4_header(ether_header, &ipv4_header) || !os_net_get_tcpudp_header(ipv4_header, &tcpudp_header))
    {
        os_debug("Not TCP/UDP over IPv4 over Ethernet");
        return;
    }

    struct lb_flow flow = {.src_ip = ipv4_header->src_addr,
                           .dst_ip = ipv4_header->dst_addr,
                           .src_port = tcpudp_header->src_port,
                           .dst_port = tcpudp_header->dst_port,
                           .protocol = ipv4_header->next_proto_id};

    time_t now = os_clock_time();

    if (packet->device != wan_device)
    {
        os_debug("Processing heartbeat, device is %" PRIu16, device);
        lb_process_heartbit(balancer, &flow, ether_header->src_addr, packet->device, now);
        return;
    }

    struct lb_backend* backend;
    if (!lb_get_backend(balancer, &flow, now, wan_device, &backend)) {
    	return;
    }

    os_debug("Processing packet from %" PRIu16 " to %" PRIu16, device, backend->nic);

    ipv4_header->dst_addr = backend->ip;
    memcpy(&ether_header->dst_addr, backend->mac, sizeof(ether_header->dst_addr));

    os_net_transmit(packet, backend->nic, ether_header, ipv4_header, tcpudp_header);
}

