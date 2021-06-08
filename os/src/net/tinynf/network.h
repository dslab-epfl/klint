// Originally from the TinyNF project, modified to use new abstractions

// Network abstractions.
// A 'device' represents a physical network card: https://en.wikipedia.org/wiki/Network_interface_controller
// Devices only handle packets destined to them by default, by looking at packets' MAC address: https://en.wikipedia.org/wiki/MAC_address
// Devices can be set into 'promiscuous' mode to handle all packets regardless of MAC address.
// Each device has one 'queue' to receive packet, and multiple 'queues' to transmit packets.
// An 'agent' handles packets received on one input device, forwarding them through zero or more output devices as needed.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/pci.h"


// Definitions (should be within ixgbe, but we need sizeof(...) to work, and let's not complicate our life with a void* driver_private or something)
// -----------

struct tn_device
{
	void* addr;
	bool rx_enabled;
	bool tx_enabled;
	uint8_t _padding[6];
};

struct tn_descriptor
{
	uint64_t addr;
	uint64_t metadata;
};

struct tn_agent
{
	uint8_t* buffer;
	volatile uint32_t* receive_tail_addr;
	size_t processed_delimiter;
	size_t outputs_count;
	size_t* lengths;
	volatile uint32_t* transmit_heads;
	volatile struct tn_descriptor** rings; // 0 == shared receive/transmit, rest are exclusive transmit
	volatile uint32_t** transmit_tail_addrs;
};

// Configuration API
// -----------------

void tn_device_init(const struct os_pci_address* pci_address, struct tn_device* device); // device must be preallocated, will be overwritten
void tn_device_set_promiscuous(struct tn_device* device);
uint64_t tn_device_get_mac(struct tn_device* device); // only the lowest 48 bits are nonzero, in big-endian

// Assumes the input should not be an output. (It'd be nice to have the flexibility, but in practice we don't need it for now)
void tn_agent_init(size_t input_index, size_t devices_count, struct tn_device* devices, struct tn_agent* agent); // agent must be preallocated, will be overwritten


// Packet processing API
// ---------------------

// Sets outputs[N] = length of the packet on device N, where 0 means drop (devices are in the order they were added)
typedef void tn_packet_handler(size_t index, uint8_t* packet, size_t length, size_t* output_lengths);
// Runs the agents forever using the given handler
_Noreturn void tn_run(size_t agents_count, struct tn_agent* agents, tn_packet_handler* handler);
