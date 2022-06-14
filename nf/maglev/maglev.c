#include "balancer.h"
#include "net/skeleton.h"
#include "os/config.h"
#include "os/log.h"
#include "os/time.h"

// Note: We assume the packets to route always arrive on the last device

static struct balancer* balancer;
static device_t devices_count;

bool nf_init(device_t _devices_count)
{
	if (_devices_count < 2) {
		return false;
	}
	devices_count = _devices_count;
	device_t backend_capacity = devices_count - 1;

	size_t flow_capacity;
	device_t cht_height;
	time_t flow_expiration_time, backend_expiration_time;
	if (!os_config_get_size("flow capacity", &flow_capacity) || !os_config_get_u16("cht height", &cht_height) || !os_config_get_time("backend expiration time", &backend_expiration_time) ||
	    !os_config_get_time("flow expiration time", &flow_expiration_time)) {
		return false;
	}

	// TODO: can we remove the need for those?
	if (cht_height == 0 || cht_height >= MAX_CHT_HEIGHT) {
		return false;
	}
	if (backend_capacity >= cht_height) {
		return false;
	}

	balancer = balancer_alloc(flow_capacity, flow_expiration_time, backend_capacity, backend_expiration_time, cht_height);
	return true;
}

void nf_handle(struct net_packet* packet)
{
	struct net_ether_header* ether_header;
	struct net_ipv4_header* ipv4_header;
	struct net_tcpudp_header* tcpudp_header;
	if (!net_get_ether_header(packet, &ether_header) || !net_get_ipv4_header(ether_header, &ipv4_header) || !net_get_tcpudp_header(ipv4_header, &tcpudp_header)) {
		os_debug("Not TCP/UDP over IPv4 over Ethernet");
		return;
	}

	if (packet->device < devices_count - 1) {
		balancer_process_heartbeat(balancer, packet->device, packet->time);
		return;
	}

	struct flow flow = {
	    .src_ip = ipv4_header->src_addr, .dst_ip = ipv4_header->dst_addr, .src_port = tcpudp_header->src_port, .dst_port = tcpudp_header->dst_port, .protocol = ipv4_header->next_proto_id};
	device_t backend;
	if (balancer_get_backend(balancer, &flow, packet->time, &backend)) {
		net_transmit(packet, backend, 0);
	}
}
