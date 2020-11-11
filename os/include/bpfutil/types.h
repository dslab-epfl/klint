#pragma once

#include <stdint.h>

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#define __be16 uint16_t
#define __be32 uint32_t
#define __be64 uint64_t

struct xdp_md {
// CHANGED from uint32_t to uintptr_t since we can't guarantee pointers will fit into 32 bits, unlike in BPF
	uintptr_t data;
	uintptr_t data_end;
// TODO necessary?
//	uint32_t data_meta;
//	uint32_t ingress_ifindex;
//	uint32_t rx_queue_index;
//	uint32_t egress_ifindex;
};
