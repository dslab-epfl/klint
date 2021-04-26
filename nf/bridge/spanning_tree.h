#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "net/packet.h"
#include "os/memory.h"
#include "os/time.h"


// in reality should be based on the links
#define LINK_COST 10


// TODO would be nice if those could be in the stp_state;
//      it's just a change to keep values that don't change within a map's lone item...
static bool* disabled_ports;
static time_t update_time;

struct stp_state {
	time_t last_update_time;
	uint64_t self;
	uint64_t root;
	uint32_t root_cost;
	device_t root_port;
	uint8_t _padding[2];
};

struct bpdu_packet {
	uint64_t root;
	uint32_t root_cost;
	uint64_t sender;
} __attribute__((packed));


static inline struct stp_state* stp_init(device_t devices_count, uint64_t self_bid, time_t update_time_)
{
	disabled_ports = os_memory_alloc(devices_count, sizeof(bool));
	update_time = update_time_;
	struct stp_state* state = os_memory_alloc(1, sizeof(struct stp_state));
	state->self = self_bid;
	state->root = self_bid;
	return state;
}

static inline bool stp_handle(struct stp_state* state, struct net_ether_header* header, struct net_packet* packet)
{
	if (packet->time > state->last_update_time + update_time) {
		state->last_update_time = packet->time;
		struct bpdu_packet* data = (struct bpdu_packet*) (header + 1);
		data->root = state->root;
		data->root_cost = state->root_cost;
		data->sender = state->self;
		packet->length = sizeof(struct net_ether_header) + sizeof(struct bpdu_packet);
		net_flood(packet, UPDATE_ETHER_ADDRS); // cannibalize the packet, simpler... sorry
		return true;
	}

	if (header->dst_addr.bytes[0] != 0x01 || header->dst_addr.bytes[1] != 0x80 || header->dst_addr.bytes[2] != 0xC2 ||
	    header->dst_addr.bytes[3] != 0x00 || header->dst_addr.bytes[4] != 0x00 || header->dst_addr.bytes[5] != 0x00) {
		return false;
	}

	struct bpdu_packet* data = (struct bpdu_packet*) (header + 1);

	if (data->root > state->root) {
		// Nope, worse root, disable that port
		disabled_ports[packet->device] = true;
		return true;
	}

	bool updated = false;
	if (data->root < state->root) {
		// Strictly better root
		state->root = data->root;
		state->root_cost = data->root_cost + LINK_COST;
		state->root_port = packet->device;
		updated = true;
	} else if (data->root == state->root && data->root_cost + LINK_COST < state->root_cost) {
		// Same root, better path
		state->root_cost = data->root_cost + LINK_COST;
		state->root_port = packet->device;
		updated = true;
	} else if (data->root == state->root && data->root_cost + LINK_COST == state->root_cost && packet->device < state->root_port) {
		// Same root, same path, tie-break via port ID
		state->root_port = packet->device;
		updated = true;
	}

	if (updated) {
		// If the info changed, broadcast it to others
		data->root = state->root;
		data->root_cost = state->root_cost;
		data->sender = state->self;
		net_flood(packet, UPDATE_ETHER_ADDRS);

		// The port to the root must be enabled
		disabled_ports[state->root_port] = false;
	}

	return true;
}

static inline bool* stp_blocked_devices(void)
{
	return disabled_ports;
}
