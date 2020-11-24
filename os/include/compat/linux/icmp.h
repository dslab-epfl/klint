#pragma once

#include "compat/linux/types.h"

#define ICMP_ECHOREPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_FRAG_NEEDED 4
#define ICMP_ECHO 8

struct icmphdr {
	__u8 type;
	__u8 code;
	__u16 checksum;
	union {
		struct {
			__u16 id;
			__u16 sequence;
		} echo;
		__u32 gateway;
		struct {
			__u16 __unused;
			__u16 mtu;
		} frag;
	} un;
} __packed;
