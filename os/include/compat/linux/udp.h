#pragma once

#include "compat/linux/types.h"

struct udphdr {
	__u16 source;
	__u16 dest;
	__u16 len;
	__u16 check;
} __packed;
