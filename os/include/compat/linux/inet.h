#pragma once

#include <stdint.h>

// https://stackoverflow.com/a/2100549/3311770
#define IS_BIG_ENDIAN (!*(unsigned char *)&(uint16_t){1})

static inline uint16_t ntohs(uint16_t netshort)
{
#ifdef IS_BIG_ENDIAN
	return netshort;
#else
	return (netshort << 8) | (netshort >> 8);
#endif
}
