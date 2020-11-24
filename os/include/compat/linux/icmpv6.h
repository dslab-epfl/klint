#pragma once

#include "compat/linux/inet.h"
#include "compat/linux/types.h"

#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PKT_TOOBIG 2
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129

struct icmp6hdr {
	__u8 icmp6_type;
	__u8 icmp6_code;
	__u16 icmp6_cksum;
	union {
		__u32 un_data32[1];
		__u16 un_data16[2];
		__u8 un_data8[4];
		struct icmpv6_echo {
			__u16 identifier;
			__u16 sequence;
		} u_echo;
		struct icmpv6_nd_advt {
#ifdef IS_BIG_ENDIAN
			__u32 router : 1,
			      solicited : 1,
			      override : 1,
			      reserved : 29;
#else
			__u32 reserved : 5,
			      override : 1,
			      solicited : 1,
			      router : 1,
			      reserved2 : 24;
#endif
		} u_nd_advt;
		struct icmpv6_nd_ra {
			__u8 hop_limit;
#ifdef IS_BIG_ENDIAN
			__u8 managed : 1,
			     other : 1,
			     home_agent : 1,
			     router_pref : 2,
			     reserved : 3;
#else
			__u8 reserved : 3,
			     router_pref : 2,
			     home_agent : 1,
			     other : 1,
			     managed : 1;
#endif
			__u16 rt_lifetime;
		} u_nd_ra;
	} icmp6_dataun;

#define icmp6_identifier        icmp6_dataun.u_echo.identifier
#define icmp6_sequence                icmp6_dataun.u_echo.sequence
#define icmp6_pointer                icmp6_dataun.un_data32[0]
#define icmp6_mtu                icmp6_dataun.un_data32[0]
#define icmp6_unused                icmp6_dataun.un_data32[0]
#define icmp6_maxdelay                icmp6_dataun.un_data16[0]
#define icmp6_router                icmp6_dataun.u_nd_advt.router
#define icmp6_solicited                icmp6_dataun.u_nd_advt.solicited
#define icmp6_override                icmp6_dataun.u_nd_advt.override
#define icmp6_ndiscreserved        icmp6_dataun.u_nd_advt.reserved
#define icmp6_hop_limit                icmp6_dataun.u_nd_ra.hop_limit
#define icmp6_addrconf_managed        icmp6_dataun.u_nd_ra.managed
#define icmp6_addrconf_other        icmp6_dataun.u_nd_ra.other
#define icmp6_rt_lifetime        icmp6_dataun.u_nd_ra.rt_lifetime
#define icmp6_router_pref        icmp6_dataun.u_nd_ra.router_pref
} __packed;
