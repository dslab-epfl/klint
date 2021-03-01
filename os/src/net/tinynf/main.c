#include "net/skeleton.h"

// TODO remove this dependency
#include <string.h>

#include "os/error.h"
#include "os/memory.h"
#include "os/pci.h"

#include "network.h"

// TODO: Explicitly verify TinyNF assumptions during verif

static device_t devices_count;
static uint8_t* device_mac_pairs;
static size_t* current_output_lengths;

void net_transmit(struct net_packet* packet, device_t device, enum net_transmit_flags flags)
{
	if ((flags & UPDATE_ETHER_ADDRS) != 0) {
		memcpy(packet->data, device_mac_pairs + 12 * device, 12);
	}

	device_t true_device = device >= packet->device ? (device - 1) : device;
if(true_device != 0) os_fatal("not zero");
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
	device_mac_pairs = os_memory_alloc(devices_count, 12);
	for (device_t n = 0; n < devices_count; n++) {
		devices[n] = tn_net_device_alloc(pci_addresses[n]);
		tn_net_device_set_promiscuous(devices[n]);
		uint64_t device_mac = tn_net_device_get_mac(devices[n]);
		// DST - TODO have it in config somehow, for now we just use a non-constant
		device_mac_pairs[n * 12 + 0] = 0;
		device_mac_pairs[n * 12 + 1] = device_mac >> 10;
		device_mac_pairs[n * 12 + 2] = device_mac >> 20;
		device_mac_pairs[n * 12 + 3] = device_mac >> 30;
		device_mac_pairs[n * 12 + 4] = device_mac >> 40;
		device_mac_pairs[n * 12 + 5] = 0;
		// SRC
		device_mac_pairs[n * 12 + 0] = device_mac >> 0;
		device_mac_pairs[n * 12 + 1] = device_mac >> 8;
		device_mac_pairs[n * 12 + 2] = device_mac >> 16;
		device_mac_pairs[n * 12 + 3] = device_mac >> 24;
		device_mac_pairs[n * 12 + 4] = device_mac >> 32;
		device_mac_pairs[n * 12 + 5] = device_mac >> 40;
	}

	struct tn_net_agent** agents = os_memory_alloc(devices_count, sizeof(struct tn_net_agent*));
	for (device_t n = 0; n < devices_count; n++) {
		agents[n] = tn_net_agent_alloc(n, devices_count, devices);
	}

	tn_net_run(devices_count, agents, tinynf_packet_handler);
}
