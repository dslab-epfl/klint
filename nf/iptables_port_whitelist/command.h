#include <stdint.h>
#include "net/packet.h"
typedef uint32_t net_ipv4_addr_t;

enum command_type
{
  Remove = 0,
  Add = 1,
};

struct ipv4_address_key
{
  bool is_dest_ip;
  net_ipv4_addr_t ipv4_addr;
} __attribute__((__packed__));

// Defines the command that must be sent to change the whitelisted Ip addresses
struct command
{
  struct ipv4_address_key key;
  uint64_t width;
  uint8_t port_bit_map[128];
  enum command_type cmd_type;
} __attribute__((__packed__));
