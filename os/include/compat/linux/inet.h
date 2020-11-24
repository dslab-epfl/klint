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

static inline uint16_t htons(uint16_t hostshort)
{
#ifdef IS_BIG_ENDIAN
	return hostshort;
#else
	return (hostshort << 8) | (hostshort >> 8);
#endif
}

static inline uint32_t htonl(uint32_t hostlong)
{
#ifdef IS_BIG_ENDIAN
	return hostlong;
#else
	return (hostlong << 24) | ((hostlong << 8) & 0xFF) | ((hostlong >> 8) & 0xFF) | (hostlong >> 24);
#endif
}
