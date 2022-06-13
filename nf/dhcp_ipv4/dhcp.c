#include "net/skeleton.h"
#include "net/packet.h"
#include "os/memory.h"
#include "structs/index_pool.h"
#include "structs/map.h"
#include "dhcp.h"

// store the list of ip addresses that can be given to clients
static uint32_t *ip_addresses;
// store the list of clients ethernet addresses
static struct net_ether_addr *eth_addresses;
static struct index_pool *index_pool;
// keep track of what client owns what ip address
static struct map *eth_index_map;
static struct net_ether_addr dhcp_server_eth_addr;
static uint32_t dhcp_server_ip;
static uint32_t subnet_mask;
static uint32_t gateway_ip;
static uint32_t dns_server_ip;
static uint32_t expiration_time;
// MAximum IPv4 mask
static const uint32_t MAX_MASK = 0xFFFFFFFF;

/**
 * @brief Update DHCP message to DHCP ack message object
 *
 * @param dhcp_header
 * @param client_ip_address
 */
void create_dhcp_ack_message(struct net_dhcp_header *dhcp_header, uint32_t client_ip_address)
{
  dhcp_header->op = BOOTREPLY;
  dhcp_header->yaddr = client_ip_address;
  struct net_dhcp_response_option *ack_option = (struct net_dhcp_response_option *)dhcp_header->options;
  set_dhcp_ack_option(ack_option);
  ack_option->dhcp_server_identifier_value = dhcp_server_ip;
  ack_option->dns_server_ip_value = dns_server_ip;
  ack_option->gateway_ip_value = gateway_ip;
  ack_option->subnet_mask_value = subnet_mask;
  ack_option->ip_address_lease_time_value = expiration_time;
}

/**
 * @brief checks if the dhcp request message is valid.
 *
 *
 * @param dhcp_header
 * @param time
 * @return true
 * @return false
 */
bool is_dhcp_request_message_accepted(struct net_dhcp_header *dhcp_header, time_t time)
{
  struct net_dhcp_request_option *request = (struct net_dhcp_request_option *)dhcp_header->options;
  size_t index;
  if (map_get(eth_index_map, &(request->client_identifier_value), &index))
  {
    if (ip_addresses[index] == request->requested_ip_address_value)
    {
      index_pool_refresh(index_pool, time, index);
      create_dhcp_ack_message(dhcp_header, ip_addresses[index]);
    }
    else
    {
      struct net_dhcp_nack_option *option = (struct net_dhcp_nack_option *)dhcp_header->options;
      set_dhcp_nack_option(option);
    }
    return true;
  }
  else
  {
    return false;
  }
}

/**
 * @brief checks if their exist a free index to allocate a new IP address
 *
 * @param dhcp_header
 * @param t
 * @return true
 * @return false
 */
bool try_create_dhcp_discover_message(struct net_dhcp_header *dhcp_header, time_t time)
{
  bool used = false;
  size_t index;
  struct net_dhcp_discover_option *discover = (struct net_dhcp_discover_option *)dhcp_header->options;
  // checks if the client ethernet address is already in the map
  if (map_get(eth_index_map, &(discover->client_identifier_value), &index))
  {
    index_pool_refresh(index_pool, time, index);
    dhcp_header->yaddr = ip_addresses[index];
  }
  else if (index_pool_borrow(index_pool, time, &index, &used))
  {
    if (used)
    {
      map_remove(eth_index_map, &eth_addresses[index]);
    }
    os_memory_copy(discover->client_identifier_value, &eth_addresses[index], sizeof(struct net_ether_addr));
    map_set(eth_index_map, &eth_addresses[index], index);
    dhcp_header->yaddr = ip_addresses[index];
  }
  // No index can be freed at this time
  else
  {
    return false;
  }
  // creating the dhcp offer message response
  struct net_dhcp_response_option *offer = (struct net_dhcp_response_option *)dhcp_header->options;
  dhcp_header->op = BOOTREPLY;
  set_dhcp_offer_option(offer);
  offer->dhcp_server_identifier_value = dhcp_server_ip;
  offer->dns_server_ip_value = dns_server_ip;
  offer->gateway_ip_value = gateway_ip;
  offer->subnet_mask_value = subnet_mask;
  offer->ip_address_lease_time_value = expiration_time;
  return true;
}

bool nf_init(device_t devices_count)
{
  // Forced to do this for the code to compile
  devices_count--;
  size_t capacity;
  if (!os_config_get_size("max number dhcp connections", &capacity))
  {
    return false;
  }
  if (!os_config_get_u32("DHCP ipv4 address", &dhcp_server_ip))
  {
    return false;
  }
  if (!os_config_get_u32("DHCP ipv4 mask", &subnet_mask))
  {
    return false;
  }
  if (!os_config_get_u32("gateway ipv4 address", &gateway_ip))
  {
    return false;
  }
  if (!os_config_get_u32("domain name server ip", &dns_server_ip))
  {
    return false;
  }
  if (!os_config_get_u32("expiration time", &expiration_time))
  {
    return false;
  }
  // using tmp to read a 6 bytes
  size_t tmp;
  if (!os_config_get_size("server ether address", &tmp))
  {
    return false;
  }
  // Copying the value read into a 6 bytes structs
  os_memory_copy(&tmp, &dhcp_server_eth_addr, sizeof(struct net_ether_addr));
  // Calculating the number of potential IP address available for the subnet mask given
  size_t num_ipv4_addr_avail = MAX_MASK - subnet_mask;
  // adjusting the capacity ensuring that it is not bigger than that of the number of IP addresses available
  // -4 represents dhcp ip, router ip, dns ip and broadcast ip
  capacity = num_ipv4_addr_avail - 4 < capacity ? num_ipv4_addr_avail - 4 : capacity;
  if (capacity <= 0)
  {
    return false;
  }
  uint32_t ip_subnet = dhcp_server_ip & subnet_mask;
  ip_addresses = os_memory_alloc(capacity, sizeof(uint32_t));
  index_pool = index_pool_alloc(capacity, expiration_time);
  eth_addresses = os_memory_alloc(capacity, sizeof(struct net_ether_addr));
  eth_index_map = map_alloc(sizeof(struct net_ether_addr), capacity);
  size_t index = 0;
  // populating our IP address array
  // TODO look at issues with loop as I should never have an illegal write
  for (uint32_t next_avail_ip = ip_subnet + 1; next_avail_ip < ip_subnet + num_ipv4_addr_avail; next_avail_ip++)
  {
    if (next_avail_ip != dhcp_server_ip && next_avail_ip != gateway_ip && next_avail_ip != dns_server_ip)
    {
      ip_addresses[index] = next_avail_ip;
      index++;
    }
    if (index == capacity)
    {
      break;
    }
  }
  return true;
}

void nf_handle(struct net_packet *packet)
{
  struct net_ether_header *eth_header;
  if (!net_get_ether_header(packet, &eth_header))
  {
    return;
  }
  struct net_ipv4_header *ip_header;
  if (!net_get_ipv4_header(eth_header, &ip_header))
  {
    return;
  }
  struct net_dhcp_header *dhcp_header;
  if (!net_get_dhcp_header(ip_header, &dhcp_header))
  {
    return;
  }
  struct net_tcpudp_header *udp_header;
  if (!net_get_tcpudp_header(ip_header, &udp_header))
  {
    return;
  }
  // bool shall_reply = false;
  // if (is_dhcp_discover_message(dhcp_header))
  // {
  //   shall_reply = try_create_dhcp_discover_message(dhcp_header, packet->time);
  // }
  // else if (is_dhcp_request_message(dhcp_header))
  // {
  //   shall_reply = is_dhcp_request_message_accepted(dhcp_header, packet->time);
  // }
  // if (shall_reply)
  // {
  //   udp_header->dst_port = 68;
  //   udp_header->src_port = 67;
  //   ip_header->src_addr = dhcp_server_ip;
  //   ip_header->dst_addr = dhcp_header->yaddr;
  //   os_memory_copy(&eth_header->dst_addr, &eth_header->src_addr, sizeof(struct net_ether_addr));
  //   os_memory_copy(&eth_header->src_addr, &dhcp_server_eth_addr, sizeof(struct net_ether_addr));
  //   // checksum of the IP header packet is ignored for now
  //   net_transmit(packet, packet->device, 0);
  // }
}