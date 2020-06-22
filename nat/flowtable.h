#pragma once

#include <stdbool.h>
#include <stdint.h>


struct flow {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	uint8_t _padding[3];
};

struct flowtable;

// Initializes a flow table. Cannot fail (unless memory allocation fails, in which case the program crashes).
struct flowtable* flowtable_init(uint16_t starting_port, int64_t expiration_time, uint64_t max_flows);

// Gets the external port associated with a given internal flow, at the given time, allocating one if needed. Fails if allocation is required but there is no more space and no flow could be expired.
bool flowtable_get_internal(struct flowtable* table, int64_t time, struct flow* flow, uint16_t* out_port);

// Gets the internal flow associated with a given external port, at the given time. Fails if there is no such flow.
bool flowtable_get_external(struct flowtable* table, int64_t time, uint16_t port, struct flow* out_flow);
