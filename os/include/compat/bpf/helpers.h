#pragma once

#include <stdint.h>

#include "os/clock.h"
#include "os/memory.h"

#include "compat/string.h"

struct xdp_md {
// CHANGED from uint32_t to uintptr_t since we can't guarantee pointers will fit into 32 bits, unlike in BPF
	uintptr_t data;
	uintptr_t data_end;
// TODO necessary?
//	uint32_t data_meta;
	uint32_t ingress_ifindex;
//	uint32_t rx_queue_index;
//	uint32_t egress_ifindex;
};

static inline long bpf_xdp_adjust_head(struct xdp_md* xdp_md, int delta)
{
	if (delta >= 0) {
		xdp_md->data += delta;
	} else {
		ptrdiff_t old_length = xdp_md->data_end - xdp_md->data;
		uint8_t* new_data = os_memory_alloc(1, old_length - delta);
		memcpy(new_data - delta, (uint8_t*) xdp_md->data, old_length);
		xdp_md->data = (uintptr_t) new_data;
		xdp_md->data_end = (uintptr_t) new_data + old_length - delta;
	}
	return 0;
}

static inline long bpf_xdp_adjust_tail(struct xdp_md* xdp_md, int delta)
{
	if (delta >= 0) {
		xdp_md->data_end -= delta;
	} else {
		ptrdiff_t old_length = xdp_md->data_end - xdp_md->data;
		uint8_t* new_data = os_memory_alloc(1, old_length - delta);
		memcpy(new_data, (uint8_t*) xdp_md->data, old_length);
		xdp_md->data = (uintptr_t) new_data;
		xdp_md->data_end = (uintptr_t) new_data + old_length - delta;
	}
	return 0;
}

// single threaded
#define bpf_get_smp_processor_id() 0

#define bpf_ktime_get_ns os_clock_time
#define bpf_ktime_get_boot_ns os_clock_time
