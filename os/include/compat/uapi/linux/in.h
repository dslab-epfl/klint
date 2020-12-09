#pragma once

#include <stdint.h>


static inline uint16_t ntohs(uint16_t netshort)
{
#if  __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return (netshort << 8) | (netshort >> 8);
#else
	return netshort;
#endif
}

static inline uint16_t htons(uint16_t hostshort)
{
#if  __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return (hostshort << 8) | (hostshort >> 8);
#else
	return hostshort;
#endif
}

static inline uint32_t htonl(uint32_t hostlong)
{
#if  __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return (hostlong << 24) | ((hostlong << 8) & 0xFF) | ((hostlong >> 8) & 0xFF) | (hostlong >> 24);
#else
	return hostlong;
#endif
}
