#pragma once

#include <stdint.h>

static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}
