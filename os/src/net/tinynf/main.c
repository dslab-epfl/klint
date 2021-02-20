#include "net/skeleton.h"

#include <string.h>

#include "os/fail.h"
#include "os/pci.h"

#include "network.h"

// change at will...
#define MAX_DEVICES 10

static device_t devices_count;
static uint8_t device_mac_pairs[12 * MAX_DEVICES];
static uint16_t* current_output_lengths;

void net_transmit(struct net_packet* packet, uint16_t device, enum net_transmit_flags flags)
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
	(void) packet;

#ifdef TN_MANY_OUTPUTS
	for (device_t n = 0; n < devices_count; n++) {
		if (n != packet->device) {
			current_output_lengths[n] = packet->length;
		}
	}
#else
	current_output_lengths[0] = packet->length;
#endif
}


static void tinynf_packet_handler(uint8_t* packet, uint16_t packet_length, void* state, uint16_t* output_lengths)
{
#ifdef TN_MANY_OUTPUTS
	for (device_t n = 0; n < devices_count; n++) {
		output_lengths[n] = 0;
	}
#else
	output_lengths[0] = 0;
#endif

	current_output_lengths = output_lengths;
	struct net_packet pkt = {
		.data = packet,
		.device = (device_t) (uintptr_t) state,
		.length = packet_length
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
		os_fail("Too many devices, increase MAX_DEVICES");
	}

	if (!nf_init(devices_count)) {
		os_fail("NF failed to init");
	}

	struct tn_net_device* devices[MAX_DEVICES];
	for (device_t n = 0; n < devices_count; n++) {
		if (!tn_net_device_init(pci_addresses[n], &(devices[n]))) {
			os_fail("Couldn't init device");
		}
		if (!tn_net_device_set_promiscuous(devices[n])) {
			os_fail("Couldn't make device promiscuous");
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
		agents[n] = tn_net_agent_alloc();
		if (!tn_net_agent_set_input(agents[n], devices[n])) {
			os_fail("Couldn't set agent RX");
		}
#ifdef TN_MANY_OUTPUTS
		for (device_t m = 0; m < devices_count; m++) {
			if (!tn_net_agent_add_output(agents[n], devices[m])) {
				os_fail("Couldn't set agent TX");
			}
		}
#else
		if (devices_count != 2) {
			os_fail("TN_MANY_OUTPUTS must be set if devices_count != 2");
		}
		if (!tn_net_agent_add_output(agents[n], devices[1 - n])) {
			os_fail("Couldn't set agent TX");
		}
#endif
	}

	tn_net_packet_handler* handlers[MAX_DEVICES];
	void* states[MAX_DEVICES];
	for (device_t n = 0; n < devices_count; n++) {
		handlers[n] = tinynf_packet_handler;
		states[n] = (void*) (uintptr_t) n;
	}
	tn_net_run(devices_count, agents, handlers, states);
}
