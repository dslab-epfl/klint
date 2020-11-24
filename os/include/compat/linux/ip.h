#pragma once

#include "compat/linux/inet.h"
#include "compat/linux/types.h"

#define IPPROTO_ICMP 1
#define IPPROTO_IPIP 4
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_IPV6 41
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ICMPV6 58

struct iphdr {
#ifdef IS_BIG_ENDIAN
	__u8 version: 4,
	     ihl: 4;
#else
	__u8 ihl: 4,
	     version: 4;
#endif
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
} __packed;
