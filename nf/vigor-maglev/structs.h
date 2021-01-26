#pragma once

#include <stdint.h>


struct lb_backend {
  uint32_t ip;
  uint16_t nic;
  uint8_t _padding[2];
};

struct lb_flow {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
  uint8_t _padding[3];
};
