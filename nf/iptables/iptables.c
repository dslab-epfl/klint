#include "net/skeleton.h"

#include "os/config.h"
#include "os/memory.h"
#include "os/time.h"
#include "structs/lpm.h"

#include "command.h"

static device_t command_device;
static device_t check_device;
static device_t send_device;

static struct lpm *iptable_lpm;
static size_t capacity;

bool is_packet_in_allowed(struct net_packet *packet)
{
  // parsing of packet and trying to cast it into its parts
  struct net_ether_header *eth_packet;
	if (!net_get_ether_header(packet, &eth_packet)) {
		return false;
	}

  struct net_ipv4_header *ipv4_packet;
	if (!net_get_ipv4_header(eth_packet, &ipv4_packet)) {
		return false;
	}

  struct net_tcpudp_header *tcpudp_packet;
	if (!net_get_tcpudp_header(ipv4_packet, &tcpudp_packet)) {
		return false;
	}

  // if ports are too large
  if(tcpudp_packet->src_port >= 1024 || tcpudp_packet->dst_port >= 1024) {
    return false;
  }

  net_ipv4_addr_t src_ip = ipv4_packet->src_addr;
  net_ipv4_addr_t dst_ip = ipv4_packet->dst_addr;

  struct ipv4_address_rule rule_src = {
    false,
    tcpudp_packet->src_port,
    src_ip,
  };
  struct ipv4_address_rule rule_dst = {
    true,
    tcpudp_packet->dst_port,
    dst_ip,
  };

  struct ipv4_address_rule rule_src_wildcard = {
    false,
    0,
    src_ip,
  };
  struct ipv4_address_rule rule_dst_wildcard = {
    true,
    0,
    dst_ip,
  };

  bool bitmap;

  if (
    (
      lpm_search(iptable_lpm, &rule_src, &bitmap) // check if it was found in the map at all
      || lpm_search(iptable_lpm, &rule_src_wildcard, &bitmap) // check if it was found in the map at all
    )
    &&
    (
      lpm_search(iptable_lpm, &rule_dst, &bitmap) // check if it was found in the map at all
      || lpm_search(iptable_lpm, &rule_dst_wildcard, &bitmap) // check if it was found in the map at all
    )
  )
  {
    return true;
  }
  return false;
}

static inline void handle_rules(struct command *cmd)
{
  if (cmd->cmd_type == Add)
  {
    bool allow = true;
    lpm_set(iptable_lpm, &cmd->rule, cmd->width, &allow);
  }
  else if (cmd->cmd_type == Remove)
  {
    lpm_remove(iptable_lpm, &cmd->rule, cmd->width);
  }
}

bool nf_init(device_t devices_count)
{
  if (devices_count != 3)
  {
    return false;
  }

  if (!os_config_get_device("check device", devices_count, &check_device) ||
      !os_config_get_device("command device", devices_count, &command_device) ||
      !os_config_get_device("send device", devices_count, &send_device) ||
      send_device == command_device || send_device == check_device || command_device == check_device)
  {
    return false;
  }

  if (!os_config_get_size("capacity", &capacity))
  {
    return false;
  }

  iptable_lpm = lpm_alloc(sizeof(struct ipv4_address_rule), sizeof(bool), capacity);

  return true;
}

void nf_handle(struct net_packet *packet)
{
  if (packet->device == check_device)
  {
    if (is_packet_in_allowed(packet))
    {
      net_transmit(packet, send_device, 0);
    }
  }
  else if (packet->device == command_device)
  {
    struct command *cmd = (struct command *)packet->data;
    if (cmd->width <= sizeof(struct ipv4_address_rule) * 8)
    {
      handle_rules(cmd);
    }
  }
}
