#ifndef _STRUCTS_H_INCLUDED_
#define _STRUCTS_H_INCLUDED_

#include <stdint.h>
#include <stddef.h>

#define ETHER_TYPE_IPv4 0x0800
#define ETHER_MAX_LEN 1518

struct ether_addr {
  uint8_t addr_bytes[6];
};

struct ether_hdr {
  struct ether_addr d_addr;
  struct ether_addr s_addr;
  uint16_t ether_type;
};

struct lb_backend {
  uint16_t nic;
  struct ether_addr mac;
  uint32_t ip;
};

struct lb_flow {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
};

struct ip_addr {
  uint32_t addr;
};

#endif //_STRUCTS_H_INCLUDED_
