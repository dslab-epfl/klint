#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/clock.h"


struct flow {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	uint8_t _padding[3];
};

struct flowtable;

// Allocates a new flow table. Cannot fail (unless memory allocation fails, in which case the program crashes).
struct flowtable* flowtable_alloc(uint16_t starting_port, time_t expiration_time, size_t max_flows);

// Gets the external port associated with a given internal flow, at the given time, allocating one if needed. Fails if allocation is required but there is no more space and no flow could be expired.
bool flowtable_get_internal(struct flowtable* table, time_t time, struct flow* flow, uint16_t* out_port);

// Gets the internal flow associated with a given external port, at the given time. Fails if there is no such flow.
bool flowtable_get_external(struct flowtable* table, time_t time, uint16_t port, struct flow* out_flow);
