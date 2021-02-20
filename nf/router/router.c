#include "net/skeleton.h"

#include "os/debug.h"

#include "lpm.h"


struct lpm* lpm;


bool nf_init(device_t max_device)
{
	(void) max_device;

	// TODO: Split allocation and fill-from-config
	lpm = lpm_alloc();

	return true;
}


void nf_handle(struct net_packet* packet)
{
	struct net_ether_header* ether_header;
	struct net_ipv4_header* ipv4_header;
	if (!net_get_ether_header(packet, &ether_header) || !net_get_ipv4_header(ether_header, &ipv4_header)) {
		os_debug("Not IPv4 over Ethernet");
		return;
	}

	if (ipv4_header->version != 4) {
		os_debug("Not IPv4");
		return;
	}

	if (ipv4_header->ihl < 5) { // ihl is in units of 4 bytes
		os_debug("IPv4 header too short");
		return;
	}

	if (ipv4_header->total_length < (ipv4_header->ihl * 4)) {
		os_debug("Total length too short");
		return;
	}

	if (!net_ipv4_checksum_valid(ipv4_header)) {
		os_debug("Bad packet checksum");
		return;
	}

	if (ipv4_header->time_to_live == 0) {
		os_debug("Packet lifetime is over");
		return;
	}

	device_t dst_device;
	uint32_t out_prefix;
	uint8_t out_prefixlen;
	if (lpm_lookup_elem(lpm, ipv4_header->dst_addr, &dst_device, &out_prefix, &out_prefixlen)) {
		net_transmit(packet, dst_device, UPDATE_ETHER_ADDRS);
	}
}
