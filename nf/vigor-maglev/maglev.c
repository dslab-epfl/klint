#include "net/skeleton.h"

#include "os/clock.h"
#include "os/config.h"
#include "os/debug.h"

#include "balancer.h"

// TODO fix formatting in maglev, and also inline stuff...

struct ld_balancer *balancer;
uint16_t wan_device;

bool nf_init(uint16_t devices_count)
{
    wan_device = os_config_get_u16("wan device");
    if (wan_device >= devices_count)
    {
        return false;
    }

    size_t flow_capacity = os_config_get_u64("flow capacity"); // TODO get_size
    if (flow_capacity > SIZE_MAX / 16 - 2) {
    	return false;
    }
    size_t cht_height = os_config_get_u64("cht height"); // TODO get_size
    if (cht_height == 0 || cht_height >= MAX_CHT_HEIGHT) {
        return false;
    }
    size_t backend_capacity = os_config_get_u64("backend capacity");
    if (backend_capacity == 0 || backend_capacity >= cht_height || backend_capacity * cht_height >= UINT32_MAX || flow_capacity > SIZE_MAX / 16 - 2) {
        return false;
    }
    time_t backend_expiration_time = os_config_get_u64("backend expiration time"); // TODO get_time
    time_t flow_expiration_time = os_config_get_u64("flow expiration time"); // TODO get_time

    balancer = ld_balancer_alloc(flow_capacity, backend_capacity, cht_height, backend_expiration_time, flow_expiration_time);

    return true;
}

void nf_handle(struct net_packet *packet)
{
    struct net_ether_header *ether_header;
    struct net_ipv4_header *ipv4_header;
    struct net_tcpudp_header *tcpudp_header;
    if (!net_get_ether_header(packet, &ether_header) || !net_get_ipv4_header(ether_header, &ipv4_header) || !net_get_tcpudp_header(ipv4_header, &tcpudp_header))
    {
        os_debug("Not TCP/UDP over IPv4 over Ethernet");
        return;
    }

    struct lb_flow flow = {.src_ip = ipv4_header->src_addr,
                           .dst_ip = ipv4_header->dst_addr,
                           .src_port = tcpudp_header->src_port,
                           .dst_port = tcpudp_header->dst_port,
                           .protocol = ipv4_header->next_proto_id};

    time_t now = os_clock_time_ns();

    if (packet->device != wan_device)
    {
        lb_process_heartbeat(balancer, &flow, packet->device, now);
        return;
    }

    struct lb_backend* backend;
    if (!lb_get_backend(balancer, &flow, now, wan_device, &backend)) {
    	return;
    }

    net_packet_checksum_update(ipv4_header, ipv4_header->dst_addr, backend->ip, true);
    ipv4_header->dst_addr = backend->ip;

    net_transmit(packet, backend->nic, 0);
}

