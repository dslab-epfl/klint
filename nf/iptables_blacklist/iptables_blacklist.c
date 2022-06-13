//
// Created by elvric on 2022-03-20.
//
#include "net/skeleton.h"

#include "os/config.h"
#include "os/memory.h"
#include "structs/lpm.h"

#include "command.h"

static device_t command_device;
static device_t check_device;
static device_t send_device;
static struct lpm *blacklist_lpm;
static size_t capacity;

static inline bool is_ip_address_in_blacklist(struct ipv4_address_rule rule)
{
  bool ignored;
  return lpm_search(blacklist_lpm, &rule, &ignored);
}

bool is_packet_in_blacklist(struct net_ipv4_header *ipv4_packet)
{
  net_ipv4_addr_t src_ip = ipv4_packet->src_addr;
  net_ipv4_addr_t dst_ip = ipv4_packet->dst_addr;
  struct ipv4_address_rule rule_src = {
      false,
      src_ip,
  };
  struct ipv4_address_rule rule_dst = {
      true,
      dst_ip};
  return is_ip_address_in_blacklist(rule_dst) || is_ip_address_in_blacklist(rule_src);
}

static inline void handle_rules(struct command *cmd)
{
  if (cmd->cmd_type == Add)
  {
    bool ignored;
    lpm_set(blacklist_lpm, &cmd->rule, cmd->width, &ignored);
  }
  else if (cmd->cmd_type == Remove)
  {
    lpm_remove(blacklist_lpm, &cmd->rule, cmd->width);
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
  if (capacity == 0)
  {
    return false;
  }
  blacklist_lpm = lpm_alloc(sizeof(struct ipv4_address_rule), sizeof(bool), capacity);
  return true;
}

void nf_handle(struct net_packet *packet)
{
  if (packet->device == check_device)
  {
    struct net_ether_header *eth_packet;
    net_get_ether_header(packet, &eth_packet);
    struct net_ipv4_header *ipv4_packet;
    if (net_get_ipv4_header(eth_packet, &ipv4_packet) && !is_packet_in_blacklist(ipv4_packet))
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
