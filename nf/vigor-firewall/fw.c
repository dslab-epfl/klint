#include "net/skeleton.h"

#include "os/clock.h"
#include "os/config.h"
#include "os/debug.h"

#include "flowtable.h"


uint16_t wan_device;
struct flowtable* table;


bool nf_init(uint16_t devices_count)
{
	if (devices_count != 2) {
		return false;
	}

	wan_device = os_config_get_u16("wan device");
	if (wan_device >= devices_count) {
		return false;
	}

	uint64_t max_flows = os_config_get_u64("max flows");
	if (max_flows == 0 || max_flows > SIZE_MAX / 16 - 2) {
		return false;
	}

	uint64_t expiration_time = os_config_get_u64("expiration time");
	table = flowtable_init(expiration_time, max_flows);

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

	uint64_t time = os_clock_time_ns();

	if (packet->device == wan_device) {
		struct flow flow = { // inverted!
			.src_port = tcpudp_header->dst_port,
			.dst_port = tcpudp_header->src_port,
			.src_ip = ipv4_header->dst_addr,
			.dst_ip = ipv4_header->src_addr,
			.protocol = ipv4_header->next_proto_id
		};
		if (!flowtable_has_external(table, time, &flow)) {
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

		flowtable_learn_internal(table, time, &flow);
	}

	net_transmit(packet, 1 - packet->device, 0);
}
