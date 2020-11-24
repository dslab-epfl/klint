#pragma once

#include "compat/linux/types.h"

struct __una_u32 { __u32 x; } __packed;

static inline __u32 __get_unaligned_cpu32(const void* p)
{
	struct __una_u32* ptr = (struct __una_u32*) p;
	return ptr->x;
}
