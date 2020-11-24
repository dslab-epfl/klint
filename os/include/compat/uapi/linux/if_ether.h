#pragma once

#include <stdint.h>

#define ETH_ALEN 6

#define ETH_P_IP 0x0800


struct ethhdr {
	uint8_t h_dest[6];
	uint8_t h_src[6];
	uint16_t h_proto;
} __attribute__((packed));
