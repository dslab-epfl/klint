#pragma once

#include "compat/linux/types.h"


#define ETH_ALEN 6

#define ETH_P_IP 0x0800


struct ethhdr {
	u8 h_dest[6];
	u8 h_src[6];
	u16 h_proto;
} __packed;
