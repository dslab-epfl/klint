#pragma once

#include <stdint.h>

#include "compat/linux/inet.h"

struct in6_addr {
	union {
		uint8_t		u6_addr8[16];
		uint16_t		u6_addr16[8];
		uint32_t		u6_addr32[4];
	} in6_u;
	#define s6_addr			in6_u.u6_addr8
	#define s6_addr16		in6_u.u6_addr16
	#define s6_addr32		in6_u.u6_addr32
} __packed;

struct ipv6hdr {
#ifdef IS_BIG_ENDIAN
	uint8_t version : 4,
	     priority : 4;
#else
	uint8_t priority : 4,
	     version : 4;
#endif
	uint8_t flow_lbl[3];
	uint16_t payload_len;
	uint8_t nexthdr;
	uint8_t hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
} __attribute__((packed));
