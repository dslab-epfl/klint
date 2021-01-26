#include "net/skeleton.h"

#include "os/clock.h"
#include "os/config.h"
#include "os/debug.h"

#include "flowtable.h"


uint32_t external_addr;
uint16_t wan_device;
struct flowtable* table;


bool nf_init(uint16_t devices_count)
{
	if (devices_count != 2) {
		return false;
	}

	external_addr = os_config_get_u32("external addr");

	wan_device = os_config_get_u16("wan device");
	if (wan_device >= devices_count) {
		return false;
	}

	uint64_t max_flows = os_config_get_u64("max flows");
	if (max_flows > SIZE_MAX / 16 - 2) {
		return false;
	}

	int64_t expiration_time = (int64_t) os_config_get_u64("expiration time");
	if (expiration_time <= 0) {
		return false;
	}

	uint16_t start_port = os_config_get_u16("start port");

	table = flowtable_alloc(start_port, expiration_time, max_flows);
	return table != 0;
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

	int64_t time = os_clock_time();

	if (packet->device == wan_device) {
		struct flow internal_flow;
		if (flowtable_get_external(table, time, tcpudp_header->dst_port, &internal_flow)) {
			if ((internal_flow.dst_ip != ipv4_header->src_addr) | (internal_flow.dst_port != tcpudp_header->src_port) | (internal_flow.protocol != ipv4_header->next_proto_id)) {
				os_debug("Spoofing attempt");
				return;
			}

			ipv4_header->dst_addr = internal_flow.src_ip;
			tcpudp_header->dst_port = internal_flow.src_port;
		} else {
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

		uint16_t external_port;
		if (!flowtable_get_internal(table, time, &flow, &external_port)) {
			os_debug("No space for the flow");
			return;
		}

		ipv4_header->src_addr = external_addr;
		tcpudp_header->src_port = external_port;
	}

	net_transmit(packet, 1 - packet->device, UPDATE_ETHER_ADDRS | UPDATE_L3_CHECKSUM | UPDATE_L4_CHECKSUM);
}
