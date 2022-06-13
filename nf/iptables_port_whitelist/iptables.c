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

static inline bool is_ip_address_and_port_in_whitelist(struct ipv4_address_key key, uint16_t port)
{
  // ports cannot be less than 1
  key.ipv4_addr += 1;
  uint8_t port_bit_map[129];
  bool key_in_map = lpm_search(blacklist_lpm, &key, &port_bit_map);
  if (key_in_map)
  {
    uint16_t bit_map_index = port / 8;
    bit_map_index = bit_map_index > 128 ? 128 : bit_map_index;
    uint8_t bit_map_byte = port_bit_map[bit_map_index];
    uint8_t bit_map_offset = port % 8;
    switch (bit_map_offset)
    {
    case 0:
      bit_map_byte = bit_map_byte & (uint8_t)0x01;
      break;
    case 1:
      bit_map_byte = bit_map_byte & (uint8_t)0x02;
      break;
    case 2:
      bit_map_byte = bit_map_byte & (uint8_t)0x04;
      break;
    case 3:
      bit_map_byte = bit_map_byte & (uint8_t)0x08;
      break;
    case 4:
      bit_map_byte = bit_map_byte & (uint8_t)0x10;
      break;
    case 5:
      bit_map_byte = bit_map_byte & (uint8_t)0x20;
      break;
    case 6:
      bit_map_byte = bit_map_byte & (uint8_t)0x40;
      break;
    case 7:
      bit_map_byte = bit_map_byte & (uint8_t)0x80;
      break;
    default:
      bit_map_byte = (uint8_t)0;
    }
    return bit_map_byte != 0;
  }
  return false;
}

bool is_packet_in_whitelist(struct net_ipv4_header *ipv4_packet)
{
  net_ipv4_addr_t src_ip = ipv4_packet->src_addr;
  net_ipv4_addr_t dst_ip = ipv4_packet->dst_addr;
  struct net_tcpudp_header *tcpudp_header;
  net_get_tcpudp_header(ipv4_packet, &tcpudp_header);
  struct ipv4_address_key key_src = {
      false,
      src_ip,
  };
  struct ipv4_address_key key_dst = {
      true,
      dst_ip};
  return is_ip_address_and_port_in_whitelist(key_dst, tcpudp_header->dst_port) && is_ip_address_and_port_in_whitelist(key_src, tcpudp_header->src_port);
}

static inline void handle_rules(struct command *cmd)
{
  if (cmd->cmd_type == Add)
  {
    lpm_set(blacklist_lpm, &cmd->key, cmd->width, &cmd->port_bit_map);
  }
  else if (cmd->cmd_type == Remove)
  {
    lpm_remove(blacklist_lpm, &cmd->key, cmd->width);
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
      send_device == command_device || send_device == check_device)
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
  blacklist_lpm = lpm_alloc(sizeof(struct ipv4_address_key), sizeof(uint8_t) * 129, capacity);
  return command_device != check_device;
}

void nf_handle(struct net_packet *packet)
{
  if (packet->device == check_device)
  {
    struct net_ether_header *eth_packet;
    net_get_ether_header(packet, &eth_packet);
    struct net_ipv4_header *ipv4_packet;
    if (net_get_ipv4_header(eth_packet, &ipv4_packet) && is_packet_in_whitelist(ipv4_packet))
    {
      net_transmit(packet, send_device, 0);
    }
  }
  else if (packet->device == command_device)
  {
    struct command *cmd = (struct command *)packet->data;
    if (cmd->width <= sizeof(struct ipv4_address_key) * 8)
    {
      handle_rules(cmd);
    }
  }
}
