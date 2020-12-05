#pragma once

#include <stdint.h>


#define IPPROTO_ICMP 1
#define IPPROTO_IPIP 4
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_IPV6 41
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ICMPV6 58

struct iphdr {
	uint8_t ihl: 4,
	        version: 4;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
} __attribute__((packed));
