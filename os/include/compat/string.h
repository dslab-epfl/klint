#pragma once

#include <stddef.h>

#include "os/memory.h"

// otherwise GCC complains those shadow existing functions... guess mem* functions have special handling for historical reasons
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"

static inline void* memcpy(void* dest, const void* src, size_t n)
{
	os_memory_copy(src, dest, n);
	return dest;
}

static inline void* memset(void* s, int c, size_t n)
{
	uint8_t* s_ = (uint8_t*) s;
	uint64_t c_ = (uint64_t) (uint8_t) c;

	while (n >= 8) {
		*((uint64_t*)s_) = (c_ << 56) | (c_ << 48) | (c_ << 40) | (c_ << 32) | (c << 24) | (c << 16) | (c << 8) | c;
		s_ += 8;
		n -= 8;
	}
	if (n >= 4) {
		*((uint32_t*)s_) = (c << 24) | (c << 16) | (c << 8) | c;
		s_ += 4;
		n -= 4;
	}
	if (n >= 2) {
		*((uint16_t*)s_) = (c << 8) | c;
		s_ += 2;
		n -= 2;
	}
	if (n == 1) {
		*s_ = c;
	}

	return s;
}

#pragma GCC diagnostic pop
