#include "net/skeleton.h"

#include "os/clock.h"
#include "os/init.h"
#include "os/log.h"
#include "os/memory.h"
#include "os/pci.h"
#include "verif/drivers.h"

#include "network.h"


static size_t devices_count;
static struct net_ether_addr* endpoint_macs;
static struct net_ether_addr* device_macs;
static size_t* current_output_lengths;


static size_t index_from_device(struct net_packet* packet, device_t device)
{
	return device > packet->device ? (device - 1) : device;
}

static device_t device_from_index(struct net_packet* packet, size_t index)
{
	return index < packet->device ? index : (index + 1);
}

static void handle_flags(struct net_packet* packet, device_t device, enum net_transmit_flags flags)
{
	if ((flags & UPDATE_ETHER_ADDRS) != 0) {
		struct net_ether_header* header = (struct net_ether_header*) packet->data;
		header->dst_addr = endpoint_macs[device];
		header->src_addr = device_macs[device];
	}
}

void net_transmit(struct net_packet* packet, device_t device, enum net_transmit_flags flags)
{
	handle_flags(packet, device, flags);
	current_output_lengths[index_from_device(packet, device)] = packet->length;
}

void net_flood(struct net_packet* packet, enum net_transmit_flags flags)
{
	for (size_t n = 0; n < devices_count - 1; n++) {
		handle_flags(packet, device_from_index(packet, n), flags);
		current_output_lengths[n] = packet->length;
	}
}

void net_flood_except(struct net_packet* packet, bool* disabled_devices, enum net_transmit_flags flags)
{
	for (size_t n = 0; n < devices_count - 1; n++) {
		device_t device = device_from_index(packet, n);
		handle_flags(packet, device, flags);
		current_output_lengths[n] = disabled_devices[device] ? 0 : packet->length;
	}
}


static void tinynf_packet_handler(size_t index, char* packet, size_t length, size_t* output_lengths)
{
	current_output_lengths = output_lengths;
	struct net_packet pkt = {
		.data = packet,
		.length = length,
		.time = os_clock_time_ns(),
		.device = (device_t) index,
	};
	nf_handle(&pkt);
}


// TODO net shouldn't be exposing a main(argc, argv), it should be OS handling this since metal doesn't need one and the args are unused...
// TODO move back the devices and agents alloc into ixgbe? they're here because I moved them while experimenting but it's weird (and remove the verif include)
int main(int argc, char** argv)
{
	(void) argc;
	(void) argv;

	os_init();

	struct os_pci_address* pci_addresses;
	devices_count = os_pci_enumerate(&pci_addresses);

	if (!nf_init(devices_count)) {
		os_debug("NF failed to init");
		return 1;
	}

	struct tn_device* devices = os_memory_alloc(devices_count, sizeof(struct tn_device));
	endpoint_macs = os_memory_alloc(devices_count, sizeof(struct net_ether_addr));
	device_macs = os_memory_alloc(devices_count, sizeof(struct net_ether_addr));
	for (size_t n = 0; n < devices_count; n++) {
		tn_device_init(&(pci_addresses[n]), &(devices[n]));
		tn_device_set_promiscuous(&(devices[n]));
		// TODO have it in config somehow, in the meantime use a non-constant
		endpoint_macs[n] = (struct net_ether_addr) { .bytes = { 0, n >> 10, n >> 20, n >> 30, n >> 40, 0 } };
		// TODO maybe network.h should directly use net_ether_addr?
		uint64_t device_mac = tn_device_get_mac(&(devices[n]));
		device_macs[n] = (struct net_ether_addr) { .bytes = { device_mac >> 0, device_mac >> 8, device_mac >> 16, device_mac >> 24, device_mac >> 32, device_mac >> 40 } };
	}

	struct tn_agent* agents = agents_alloc(devices_count, sizeof(struct tn_agent));
	for (size_t n = 0; n < devices_count; n++) {
		tn_agent_init(n, devices_count, devices, &(agents[n]));
	}

	tn_run(devices_count, agents, tinynf_packet_handler);
}
