#pragma once

#include <stdint.h>

#define ICMP_ECHOREPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_FRAG_NEEDED 4
#define ICMP_ECHO 8

struct icmphdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	union {
		struct {
			uint16_t id;
			uint16_t sequence;
		} echo;
		uint32_t gateway;
		struct {
			uint16_t __unused;
			uint16_t mtu;
		} frag;
	} un;
} __attribute__((packed));
