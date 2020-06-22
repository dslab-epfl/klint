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

struct flowtable* flowtable_init(int64_t expiration_time, uint64_t max_flows);

void flowtable_learn_internal(struct flowtable* table, int64_t time, struct flow* flow);

bool flowtable_has_external(struct flowtable* table, int64_t time, struct flow* flow);
