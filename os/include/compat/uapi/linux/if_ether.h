#pragma once

#include <stdint.h>

#define ETH_ALEN 6

#define ETH_P_IP 0x0800
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

struct ethhdr {
	uint8_t h_dest[6];
	uint8_t h_source[6];
	uint16_t h_proto;
} __attribute__((packed));
