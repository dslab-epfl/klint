// Originally from the TinyNF project, slightly modified to use the new abstractions
// The main visible change is the move from a bool* to an uint16_t* for outputs, to allow per-output length

// Network abstractions.
// A 'device' represents a physical network card: https://en.wikipedia.org/wiki/Network_interface_controller
// Devices only handle packets destined to them by default, by looking at packets' MAC address: https://en.wikipedia.org/wiki/MAC_address
// Devices can be set into 'promiscuous' mode to handle all packets regardless of MAC address.
// Each device has one 'queue' to receive packet, and multiple 'queues' to transmit packets.
// An 'agent' handles packets received on one input device, forwarding them through zero or more output devices as needed.

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "os/pci.h"


// Configuration API
// -----------------

struct tn_net_device;
struct tn_net_agent;

bool tn_net_device_init(struct os_pci_address pci_address, struct tn_net_device** out_device);
bool tn_net_device_set_promiscuous(struct tn_net_device* device);
uint64_t tn_net_device_get_mac(struct tn_net_device* device); // only the lowest 48 bits are nonzero, in big-endian

struct tn_net_agent* tn_net_agent_alloc(size_t outputs_count);
bool tn_net_agent_set_input(struct tn_net_agent* agent, struct tn_net_device* device);
bool tn_net_agent_add_output(struct tn_net_agent* agent, struct tn_net_device* device);


// Packet processing API
// ---------------------

// Sets outputs[N] = length of the packet on queue N, where 0 means drop (queues are in the order they were added)
typedef void tn_net_packet_handler(uint8_t* packet, size_t packet_length, void* state, size_t* output_lengths);
// Runs the agents forever using the given handlers
_Noreturn void tn_net_run(size_t agents_count, struct tn_net_agent** agents, tn_net_packet_handler** handlers, void** states);
