#include "net/skeleton.h"

#include "os/error.h"
#include "os/memory.h"
#include "os/pci.h"

#include "network.h"

// TODO: Explicitly verify TinyNF assumptions during verif

static device_t devices_count;
static struct net_ether_addr* endpoint_macs;
static struct net_ether_addr* device_macs;
static size_t* current_output_lengths;

void net_transmit(struct net_packet* packet, device_t device, enum net_transmit_flags flags)
{
	if ((flags & UPDATE_ETHER_ADDRS) != 0) {
		struct net_ether_header* header = (struct net_ether_header*) packet->data;
		header->dst_addr = endpoint_macs[device];
		header->src_addr = device_macs[device];
	}

	device_t true_device = device >= packet->device ? (device - 1) : device;
	current_output_lengths[true_device] = packet->length;
}

void net_flood(struct net_packet* packet)
{
	for (device_t n = 0; n < devices_count - 1; n++) {
		current_output_lengths[n] = packet->length;
	}
}


static void tinynf_packet_handler(size_t index, uint8_t* packet, size_t length, size_t* output_lengths)
{
	current_output_lengths = output_lengths;
	struct net_packet pkt = {
		.data = packet,
		.device = (device_t) index,
		.length = length
	};
	nf_handle(&pkt);
}

int main(int argc, char** argv)
{
	(void) argc;
	(void) argv;

	struct os_pci_address* pci_addresses;
	devices_count = os_pci_enumerate(&pci_addresses);

	if (!nf_init(devices_count)) {
		os_fatal("NF failed to init");
	}

	struct tn_net_device** devices = os_memory_alloc(devices_count, sizeof(struct tn_net_device*));;
	endpoint_macs = os_memory_alloc(devices_count, sizeof(struct net_ether_addr));
	device_macs = os_memory_alloc(devices_count, sizeof(struct net_ether_addr));
	for (device_t n = 0; n < devices_count; n++) {
		devices[n] = tn_net_device_alloc(pci_addresses[n]);
		tn_net_device_set_promiscuous(devices[n]);
		uint64_t device_mac = tn_net_device_get_mac(devices[n]);
		// DST - TODO have it in config somehow, for now we just use a non-constant
		endpoint_macs[n] = (struct net_ether_addr) { .bytes = { 0, device_mac >> 10, device_mac >> 20, device_mac >> 30, device_mac >> 40, 0 } };
		// SRC
		device_macs[n] = (struct net_ether_addr) { .bytes = { device_mac >> 0, device_mac >> 8, device_mac >> 16, device_mac >> 24, device_mac >> 32, device_mac >> 40 } };
	}

	struct tn_net_agent** agents = os_memory_alloc(devices_count, sizeof(struct tn_net_agent*));
	for (device_t n = 0; n < devices_count; n++) {
		agents[n] = tn_net_agent_alloc(n, devices_count, devices);
	}

	tn_net_run(devices_count, agents, tinynf_packet_handler);
}
