#include "net/skeleton.h"

#include "os/fail.h"
#include "os/pci.h"

#include "network.h"

// change at will...
#define MAX_DEVICES 10

static size_t devices_count;
static bool* current_outputs;

void os_net_transmit(struct os_net_packet* packet, uint16_t device)
{
	current_outputs[device] = true;
}

void os_net_flood(struct os_net_packet* packet)
{
#ifdef TN_MANY_OUTPUTS
	for (size_t n = 0; n < devices_count; n++) {
		current_outputs[n] = (n != packet->device);
	}
#else
	current_outputs[0] = true;
#endif
}


static uint16_t tinynf_packet_handler(uint8_t* packet, uint16_t packet_length, void* state, bool* outputs)
{
#ifdef TN_MANY_OUTPUTS
	for (size_t n = 0; n < devices_count; n++) {
		outputs[n] = false;
	}
#else
	outputs[0] = false;
#endif

	current_outputs = outputs;
	struct os_net_packet packet = {
		.data = packet,
		.device = (uint16_t) state,
		.length = packet_length
	};

	nf_handle(&packet);

	return packet.length;
}

int main(int argc, char** argv)
{
	struct tn_pci_address* pci_addresses;
	devices_count = os_pci_enumerate(&pci_addresses);
	if (devices_count > max_devices) {
		os_fail("Too many devices, increase MAX_DEVICES");
	}

	if (!nf_init(devices_count)) {
		os_fail("NF failed to init");
	}

	struct tn_net_device* devices[MAX_DEVICES];
	for (size_t n = 0; n < devices_count; n++) {
		if (!tn_net_device_init(pci_addresses[n], &(devices[n]))) {
			os_fail("Couldn't init device");
		}
		if (!tn_net_device_set_promiscuous(devices[n])) {
			os_fail("Couldn't make device promiscuous");
		}
	}

	struct tn_net_agent* agents[MAX_DEVICES];
	for (size_t n = 0; n < devices_count; n++) {
		if (!tn_net_agent_init(&(agents[n]))) {
			os_fail("Couldn't init agent");
		}
		if (!tn_net_agent_set_input(agents[n], devices[n])) {
			os_fail("Couldn't set agent RX");
		}
#ifdef TN_MANY_OUTPUTS
		for (size_t m = 0; m < devices_count; m++) {
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
	for (uint16_t n = 0; n < devices_count; n++) {
		handlers[n] = tinynf_packet_handler;
		states[n] = (void*) n;
	}
	tn_net_run(devices_count, agents, handlers, states);
}
