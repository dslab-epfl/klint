#include "net/packet.h"

#include <stdint.h>
typedef uint32_t net_ipv4_addr_t;

enum command_type {
	Remove = 0,
	Add = 1,
};

struct ipv4_address_rule {
	bool is_dest_ip;
	uint16_t dst_port;
	net_ipv4_addr_t ipv4_addr;
} __attribute__((__packed__));

// Defines the command that must be sent to change the whitelisted Ip addresses
struct command {
	struct ipv4_address_rule rule;
	uint64_t width;
	enum command_type cmd_type;
} __attribute__((__packed__));
