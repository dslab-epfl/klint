#pragma once

#include <stdint.h>

#include "net/packet.h"


struct lb_backend {
  uint16_t nic;
  net_ether_addr_t mac;
  uint32_t ip;
  uint8_t _padding[4];
};

struct lb_flow {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
  uint8_t _padding[3];
};
