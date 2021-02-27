#include "net/skeleton.h"

#include <string.h>

#include "os/error.h"
#include "os/pci.h"

#include "network.h"

// change at will... TODO remove it entirely
#define MAX_DEVICES 10
#define TN_MANY_OUTPUTS

static device_t devices_count;
static uint8_t device_mac_pairs[12 * MAX_DEVICES];
static size_t* current_output_lengths;

void net_transmit(struct net_packet* packet, device_t device, enum net_transmit_flags flags)
{
	// TODO: Explicitly verify TinyNF assumptions during verif (including TN_MANY_OUTPUTS)
	if (flags & UPDATE_ETHER_ADDRS) {
		memcpy(packet->data, device_mac_pairs + 12 * device, 12);
	}

#ifdef TN_MANY_OUTPUTS
	current_output_lengths[device] = packet->length;
#else
	current_output_lengths[0] = packet->length;
#endif
}

void net_flood(struct net_packet* packet)
{
#ifdef TN_MANY_OUTPUTS
	for (device_t n = 0; n < devices_count; n++) {
		current_output_lengths[n] = packet->length;
	}
	current_output_lengths[packet->device] = 0;
#else
	current_output_lengths[0] = packet->length;
#endif
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
	if (devices_count > MAX_DEVICES) {
		os_fatal("Too many devices, increase MAX_DEVICES");
	}

	if (!nf_init(devices_count)) {
		os_fatal("NF failed to init");
	}

	struct tn_net_device* devices[MAX_DEVICES];
	for (device_t n = 0; n < devices_count; n++) {
		if (!tn_net_device_init(pci_addresses[n], &(devices[n]))) {
			os_fatal("Couldn't init device");
		}
		if (!tn_net_device_set_promiscuous(devices[n])) {
			os_fatal("Couldn't make device promiscuous");
		}
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

	struct tn_net_agent* agents[MAX_DEVICES];
	for (device_t n = 0; n < devices_count; n++) {
		agents[n] = tn_net_agent_alloc(
#ifdef TN_MANY_OUTPUTS
devices_count
#else
1
#endif
		);
		if (!tn_net_agent_set_input(agents[n], devices[n])) {
			os_fatal("Couldn't set agent RX");
		}
#ifdef TN_MANY_OUTPUTS
		for (device_t m = 0; m < devices_count; m++) {
			if (!tn_net_agent_add_output(agents[n], devices[m])) {
				os_fatal("Couldn't set agent TX");
			}
		}
#else
		if (devices_count != 2) {
			os_fatal("TN_MANY_OUTPUTS must be set if devices_count != 2");
		}
		if (!tn_net_agent_add_output(agents[n], devices[1 - n])) {
			os_fatal("Couldn't set agent TX");
		}
#endif
	}

	tn_net_run(devices_count, agents, tinynf_packet_handler);
}
