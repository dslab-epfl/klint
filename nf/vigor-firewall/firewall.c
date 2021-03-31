#include "net/skeleton.h"

#include "os/clock.h"
#include "os/config.h"
#include "os/log.h"

#include "flow_table.h"


static device_t wan_device;
static struct flow_table* table;


bool nf_init(device_t devices_count)
{
	if (devices_count != 2) {
		return false;
	}

	time_t expiration_time;
	size_t max_flows;
	if (!os_config_get_device("wan device", devices_count, &wan_device) || !os_config_get_time("expiration time", &expiration_time) || !os_config_get_size("max flows", &max_flows)) {
		return false;
	}

	table = flow_table_alloc(expiration_time, max_flows);
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

	time_t time = os_clock_time_ns();

	if (packet->device == wan_device) {
		struct flow flow = { // inverted!
			.src_port = tcpudp_header->dst_port,
			.dst_port = tcpudp_header->src_port,
			.src_ip = ipv4_header->dst_addr,
			.dst_ip = ipv4_header->src_addr,
			.protocol = ipv4_header->next_proto_id
		};
		if (!flow_table_has_external(table, time, &flow)) {
			os_debug("Unknown flow");
			return;
		}
	} else {
		struct flow flow = {
			.src_port = tcpudp_header->src_port,
			.dst_port = tcpudp_header->dst_port,
			.src_ip = ipv4_header->src_addr,
			.dst_ip = ipv4_header->dst_addr,
			.protocol = ipv4_header->next_proto_id,
		};

		flow_table_learn_internal(table, time, &flow);
	}

	net_transmit(packet, 1 - packet->device, 0);
}
