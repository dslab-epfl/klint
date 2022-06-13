#include "net/skeleton.h"

#include "os/config.h"
#include "local_map.h"
#include "os/memory.h"
#include "net/packet.h"
#include "local_os_changes.h"
#include "dns_record.h"

static struct map *net_dns_record_map;
static device_t command_device;
static device_t regular_device;

void prepare_dns_response_error_header(struct net_dns_header *dns_header, uint16_t rcode)
{
  // Set as response packet
  dns_header->options = dns_header->options | 0x80;
  // fill in status code
  dns_header->options = dns_header->options & rcode;
}

bool nf_init(device_t devices_count)
{
  if (devices_count != 2)
  {
    return false;
  }
  size_t capacity;
  if (!os_config_get_size("max number of dns records", &capacity) ||
      !os_config_get_device("command device", devices_count, &command_device) ||
      !os_config_get_device("regular device", devices_count, &regular_device))
  {
    return false;
  }
  net_dns_record_map = map_alloc(64, sizeof(struct net_dns_record), capacity);
  return true;
}

void nf_handle(struct net_packet *packet)
{

  // DNS packet received is a query
  if (packet->device == regular_device)
  {
    struct net_ether_header *ether_header;
    net_get_ether_header(packet, &ether_header);
    struct net_ipv4_header *ip_header;
    net_get_ipv4_header(ether_header, &ip_header);
    struct net_tcpudp_header *udp_header;
    net_get_tcpudp_header(ip_header, &udp_header);
    struct net_dns_header *dns_header;

    // Check if the DNS request is valid if not we just drop it
    if (!net_get_dns_header(ip_header, &dns_header))
    {
      return;
    }

    // else if question sections have multiple entries
    if (dns_header->question_count != 1 || dns_header->answer_count != 0)
    {
      prepare_dns_response_error_header(dns_header, 0xFFF4);
    }

    struct net_dns_record *tmp_rec;
    struct net_dns_answer_entry dns_answer_entry;
    size_t after_question_pointer = net_get_dns_question_entry(dns_header->data, &dns_answer_entry);

    // the one is none a-records type
    if (dns_answer_entry.qtype != 1 || dns_answer_entry.qclass != 1)
    {
      prepare_dns_response_error_header(dns_header, 0xFFF4);
    }
    // if requested NAME is not in dns-entries map
    if (!map_get(net_dns_record_map, dns_answer_entry.qname, &tmp_rec))
    {
      prepare_dns_response_error_header(dns_header, 0xFFF3);
    }
    else
    {
      // construct the ressource object
      prepare_dns_response(after_question_pointer, tmp_rec, dns_header);
    }

    // Preparing response packet
    // TODO prepare response packet (modify the dns_header)
    struct net_ether_addr tmp_dst_eth_add = ether_header->dst_addr;
    ether_header->src_addr = ether_header->dst_addr;
    ether_header->dst_addr = tmp_dst_eth_add;

    uint32_t tmp_src_ipv4 = ip_header->src_addr;
    ip_header->src_addr = ip_header->dst_addr;
    ip_header->dst_addr = tmp_src_ipv4;

    uint16_t tmp_src_port = udp_header->src_port;
    udp_header->src_port = udp_header->dst_port;
    udp_header->dst_port = tmp_src_port;

    net_transmit(packet, packet->device, 0);
  }
  // DNS packet is an update to the map
  else if (packet->device == command_device)
  {
    struct command *cmd = (struct command *)packet->data;
    if (cmd->cmd_type == ADD)
    {
      map_set(net_dns_record_map, &cmd->record.host, &cmd->record);
    }
    else if (cmd->cmd_type == REMOVE)
    {
      map_remove(net_dns_record_map, &cmd->record.host);
    }
  }
}
