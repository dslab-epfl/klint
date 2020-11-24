#pragma once

#include "compat/linux/inet.h"
#include "compat/linux/types.h"

struct tcphdr {
	__u16 source;
	__u16 dest;
	__u32 seq;
	__u32 ack_seq;
#ifdef IS_BIG_ENDIAN
	__u16 doff : 4,
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
	__u16 res1 : 4,
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
	__u16 window;
	__u16 check;
	__u16 urg_ptr;
} __packed;
