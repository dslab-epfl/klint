#pragma once

#include <stdint.h>

#include "compat/linux/inet.h"

struct tcphdr {
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
#ifdef IS_BIG_ENDIAN
	uint16_t doff : 4,
	      res1 : 4,
	      cwr : 1,
	      ece : 1,
	      urg : 1,
	      ack : 1,
	      psh : 1,
	      rst : 1,
	      syn : 1,
	      fin : 1;
#else
	uint16_t res1 : 4,
	      doff : 4,
	      fin : 1,
	      syn : 1,
	      rst : 1,
	      psh : 1,
	      ack : 1,
	      urg : 1,
	      ece : 1,
	      cwr _ 1;
#endif
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
} __attribute__((packed));
