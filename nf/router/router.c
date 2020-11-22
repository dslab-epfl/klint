#include "os/skeleton/nf.h"

#include "os/memory.h"
#include "os/debug.h"

#include "lpm.h"

struct lpm* lpm;

bool nf_init(uint16_t devices_count)
{
	(void) devices_count;

	// Initialize forwarding table
	lpm = lpm_alloc();
	// ??? update it        lpm_update_elem(lpm, n << 24, 8, 1);
	return true;
}

void nf_handle(struct os_net_packet* packet)
{
	struct os_net_ether_header* ether_header;
	struct os_net_ipv4_header* ipv4_header;
	if (!os_net_get_ether_header(packet, &ether_header) || !os_net_get_ipv4_header(ether_header, &ipv4_header)) {
		os_debug("Not IPv4 over Ethernet");
		return;
	}

	uint16_t dst_device;
	uint32_t out_prefix;
	uint8_t out_prefixlen;
	if (lpm_lookup_elem(lpm, ipv4_header->dst_addr, &dst_device, &out_prefix, &out_prefixlen)) {
		os_net_transmit(packet, dst_device, ether_header, ipv4_header, NULL);
	}
}
