#pragma once

#include <stdint.h>

struct __una_u32 { uint32_t x; } __attribute__((packed));

static inline uint32_t __get_unaligned_cpu32(const void* p)
{
	struct __una_u32* ptr = (struct __una_u32*) p;
	return ptr->x;
}
