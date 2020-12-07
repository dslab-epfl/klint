#pragma once

#include <stdint.h>

#include "os/network.h"


struct lb_backend {
  uint16_t nic;
  uint8_t mac[OS_NET_ETHER_ADDR_SIZE];
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
