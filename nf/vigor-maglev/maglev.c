#include "net/skeleton.h"

#include "os/clock.h"
#include "os/config.h"
#include "os/log.h"

#include "balancer.h"


static struct balancer *balancer;
static device_t wan_device;


bool nf_init(device_t devices_count)
{
	if (devices_count < 2) {
		return false;
	}

	wan_device = os_config_get_device("wan device", devices_count);

	size_t flow_capacity = os_config_get_size("flow capacity");
	size_t cht_height = os_config_get_size("cht height");
	if (cht_height == 0 || cht_height >= MAX_CHT_HEIGHT) { // TODO what can we do about this?
		return false;
	}
	size_t backend_capacity = os_config_get_size("backend capacity");
	if (backend_capacity == 0 || backend_capacity >= cht_height || backend_capacity * cht_height >= UINT32_MAX) { // TODO and this?
		return false;
	}
	time_t backend_expiration_time = os_config_get_time("backend expiration time");
	time_t flow_expiration_time = os_config_get_time("flow expiration time");

	balancer = balancer_alloc(flow_capacity, flow_expiration_time, backend_capacity, backend_expiration_time, cht_height);

	return true;
}

void nf_handle(struct net_packet *packet)
{
	struct net_ether_header *ether_header;
	struct net_ipv4_header *ipv4_header;
	struct net_tcpudp_header *tcpudp_header;
	if (!net_get_ether_header(packet, &ether_header) || !net_get_ipv4_header(ether_header, &ipv4_header) || !net_get_tcpudp_header(ipv4_header, &tcpudp_header)) {
		os_debug("Not TCP/UDP over IPv4 over Ethernet");
		return;
	}

	struct flow flow = {
		.src_ip = ipv4_header->src_addr,
		.dst_ip = ipv4_header->dst_addr,
		.src_port = tcpudp_header->src_port,
		.dst_port = tcpudp_header->dst_port,
		.protocol = ipv4_header->next_proto_id
	};

	time_t now = os_clock_time_ns();

	if (packet->device == wan_device) {
		struct backend* backend;
		if (!balancer_get_backend(balancer, &flow, now, &backend)) {
			return;
		}

		net_packet_checksum_update(ipv4_header, ipv4_header->dst_addr, backend->ip, true);
		ipv4_header->dst_addr = backend->ip;

		net_transmit(packet, backend->device, 0);
	}

	balancer_process_heartbeat(balancer, &flow, packet->device, now);
}
