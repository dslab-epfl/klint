#pragma once

#include <stdint.h>


static inline uint64_t msr_read(uint64_t index)
{
	uint64_t result;
	__asm__ volatile ("rdmsr" : "=A" (result) : "c" ((uint32_t) index));
	return result;
}
