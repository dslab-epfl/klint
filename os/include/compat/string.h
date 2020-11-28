#pragma once

#include <stddef.h>

// Try to access as wide a width as possible, both faster at runtime and for symbex

// otherwise GCC complains those shadow existing functions... guess mem* functions have special handling for historical reasons
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"

static inline void* memcpy(void* dest, const void* src, size_t n)
{
	const uint8_t* src_ = (const uint8_t*) src;
	uint8_t* dst_ = (uint8_t*) dest;

	while (n >= 8) {
		*((uint64_t*)dst_) = *((const uint64_t*)src_);
		dst_ += 8;
		src_ += 8;
		n -= 8;
	}
	if (n >= 4) {
		*((uint32_t*)dst_) = *((const uint32_t*)src_);
		dst_ += 4;
		src_ += 4;
		n -= 4;
	}
	if (n >= 2) {
		*((uint16_t*)dst_) = *((const uint16_t*)src_);
		dst_ += 2;
		src_ += 2;
		n -= 2;
	}
	if (n == 1) {
		*dst_ = *src_;
	}

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
