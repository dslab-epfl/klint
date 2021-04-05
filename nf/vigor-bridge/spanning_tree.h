#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "net/packet.h"
#include "os/memory.h"


// in reality should be based on the links
#define LINK_COST 10

struct stp_state {
	bool* ports_disabled;
	uint64_t* ports_bid;
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


static inline struct stp_state* stp_init(device_t devices_count, uint64_t self_bid)
{
	struct stp_state* state = os_memory_alloc(1, sizeof(struct stp_state));
	state->ports_disabled = os_memory_alloc(devices_count, sizeof(bool));
	state->ports_bid = os_memory_alloc(devices_count, sizeof(uint64_t));
	state->self = self_bid;
	state->root = self_bid;
	return state;
}

static inline bool stp_handle(struct stp_state* state, struct net_packet* packet)
{
	struct net_ether_header* header;
	if (!net_get_ether_header(packet, &header)) {
		return false;
	}

	if (header->dst_addr.bytes[0] != 0x01 || header->dst_addr.bytes[1] != 0x80 || header->dst_addr.bytes[2] != 0xC2 ||
	    header->dst_addr.bytes[3] != 0x00 || header->dst_addr.bytes[4] != 0x00 || header->dst_addr.bytes[5] != 0x00) {
		return false;
	}

	struct bpdu_packet* data = (struct bpdu_packet*) (header + 1);

	state->ports_bid[packet->device] = data->sender;

	bool updated = false;
	uint64_t old_root = state->root;
	if (data->root < state->root) {
		state->root = data->root;
		state->root_cost = data->root_cost + LINK_COST;
		state->root_port = packet->device;
		updated = true;
	} else if (data->root == state->root && data->root_cost + LINK_COST < state->root_cost) {
		state->root_cost = data->root_cost + LINK_COST;
		state->root_port = packet->device;
		updated = true;
	} else if (data->root == state->root && data->root_cost + LINK_COST == state->root_cost && packet->device < state->root_port) {
		state->root_port = packet->device;
		updated = true;
	}

	if (updated) {
		data->root = state->root;
		data->root_cost = state->root_cost;
		data->sender = state->self;
		net_flood(packet, UPDATE_ETHER_ADDRS);
		state->ports_disabled[state->root] = false;
		state->ports_disabled[old_root] = state->self > state->ports_bid[old_root];
	}

	return true;
}

static inline bool* stp_blocked_devices(struct stp_state* state)
{
	return state->ports_disabled;
}
