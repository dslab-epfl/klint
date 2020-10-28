#include "os/skeleton/nf.h"

#include "os/clock.h"
#include "os/memory.h"
#include "os/debug.h"

#include "lpm.h"

struct lpm *lpm;

bool nf_init(uint16_t devices_count __attribute__((unused)))
{
    // Initialize forwarding table
    if (!lpm_allocate(&lpm)) {
        return false;
    }
    // for (uint32_t n = 0; n < 128; n++)
    // {
    //     lpm_update_elem(lpm, n << 24, 8, 1);
    // }
    // for (uint32_t n = 0; n < 128; n++)
    // {
    //     lpm_update_elem(lpm, n, 32, 1);
    // }
    return true;
}

void nf_handle(struct os_net_packet *packet)
{
    struct os_net_ether_header *ether_header;
    struct os_net_ipv4_header *ipv4_header;
    if (!os_net_get_ether_header(packet, &ether_header) || !os_net_get_ipv4_header(ether_header, &ipv4_header))
    {
        os_debug("Not IPv4 over Ethernet");
        return;
    }

    uint16_t dst_device = lpm_lookup_elem(lpm, ipv4_header->dst_addr);
    // if (dst_device == mbuf->port)
    //     return mbuf->port;

	os_net_transmit(packet, dst_device, ether_header, ipv4_header, NULL);
}
