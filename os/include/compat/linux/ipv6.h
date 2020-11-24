#pragma once

#include "compat/linux/inet.h"
#include "compat/linux/types.h"

struct in6_addr {
	union {
		__u8		u6_addr8[16];
		__u16		u6_addr16[8];
		__u32		u6_addr32[4];
	} in6_u;
	#define s6_addr			in6_u.u6_addr8
	#define s6_addr16		in6_u.u6_addr16
	#define s6_addr32		in6_u.u6_addr32
	#endif
} __packed;

struct ipv6hdr {
	__u8 priority : 4,
	     version : 4;
	__u8 flow_lbl[3];
	__u16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
} __packed;
