#pragma once

static inline uint64_t msr_read(uint64_t index)
{
	uint64_t result;
	// volatile because the result might change even for the same call
	__asm__ volatile ("rdmsr" : "=A" (msr_value) : "c" ((uint32_t) index));
	return result;
}
