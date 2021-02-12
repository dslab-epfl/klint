#pragma once

// Basic hardware-independent implementation of rte_memcpy.h

#include <stdint.h>
#include <string.h>


static inline void rte_mov16(uint8_t* dst, const uint8_t* src)
{
	*((uint16_t*)dst) = *((uint16_t*)src);
}

static inline void rte_mov32(uint8_t* dst, const uint8_t* src)
{
	*((uint32_t*)dst) = *((uint32_t*)src);
}

static inline void rte_mov48(uint8_t* dst, const uint8_t* src)
{
	rte_mov32(dst, src);
	rte_mov16(dst + 4, src + 4);
}

static inline void rte_mov64(uint8_t* dst, const uint8_t* src)
{
	*((uint64_t*)dst) = *((uint64_t*)src);
}

static inline void rte_mov128(uint8_t* dst, const uint8_t* src)
{
	rte_mov64(dst, src);
	rte_mov64(dst + 8, src + 8);
}

static inline void rte_mov256(uint8_t* dst, const uint8_t* src)
{
	rte_mov128(dst, src);
	rte_mov128(dst + 16, src + 16);
}

static void* rte_memcpy(void* dst, const void* src, size_t n)
{
	memcpy(dst, src, n);
}
