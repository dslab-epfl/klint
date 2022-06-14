#include "flow_table.h"
#include "net/skeleton.h"
#include "os/config.h"
#include "os/log.h"
#include "os/time.h"

static uint32_t external_addr;
static device_t wan_device;
static struct flow_table* table;

bool nf_init(device_t devices_count)
{
	if (devices_count != 2) {
		return false;
	}

	size_t max_flows;
	time_t expiration_time;
	uint16_t start_port;
	if (!os_config_get_u32("external addr", &external_addr) || !os_config_get_device("wan device", devices_count, &wan_device) || !os_config_get_size("max flows", &max_flows) ||
	    !os_config_get_time("expiration time", &expiration_time) || !os_config_get_u16("start port", &start_port)) {
		return false;
	}

	table = flow_table_alloc(start_port, expiration_time, max_flows);
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

	if (packet->device == wan_device) {
		struct flow internal_flow;
		if (flow_table_get_external(table, packet->time, tcpudp_header->dst_port, &internal_flow)) {
			if ((internal_flow.dst_ip != ipv4_header->src_addr) || (internal_flow.dst_port != tcpudp_header->src_port) || (internal_flow.protocol != ipv4_header->next_proto_id)) {
				os_debug("Spoofing attempt");
				return;
			}

			net_packet_checksum_update_32(ipv4_header, ipv4_header->dst_addr, internal_flow.src_ip, true);
			net_packet_checksum_update(ipv4_header, tcpudp_header->dst_port, internal_flow.src_port, false);
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
		if (!flow_table_get_internal(table, packet->time, &flow, &external_port)) {
			os_debug("No space for the flow");
			return;
		}

		net_packet_checksum_update_32(ipv4_header, ipv4_header->src_addr, external_addr, true);
		net_packet_checksum_update(ipv4_header, tcpudp_header->src_port, external_port, false);
		ipv4_header->src_addr = external_addr;
		tcpudp_header->src_port = external_port;
	}

	net_transmit(packet, 1 - packet->device, UPDATE_ETHER_ADDRS);
}
