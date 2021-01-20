#pragma once

#include <stdbool.h>
#include <stdint.h>

#define OS_NET_ETHER_ADDR_SIZE 6
typedef uint8_t os_net_ether_addr_t[OS_NET_ETHER_ADDR_SIZE];

// Packet received on a device
// HACK: It's really a DPDK mbuf we hide
struct os_net_packet {
	uint8_t* data;
	uint64_t _reserved0; // DPDK buf_iova
	uint16_t _reserved1; // DPDK data_off
	uint16_t _reserved2; // DPDK refcnt
	uint16_t _reserved3; // DPDK nb_segs
	uint16_t device;
	uint64_t _reserved4; // DPDK ol_flags
	uint32_t _reserved5; // DPDK packet_type
	uint32_t _reserved6; // DPDK pkt_len
	uint16_t length;
} __attribute__((packed));

// Ethernet header
struct os_net_ether_header
{
	uint8_t dst_addr[OS_NET_ETHER_ADDR_SIZE];
	uint8_t src_addr[OS_NET_ETHER_ADDR_SIZE];
	uint16_t ether_type;
} __attribute__((__packed__));

// IPv4 header
struct os_net_ipv4_header
{
	uint8_t  version : 4,
	         ihl : 4;
	uint8_t  type_of_service;
	uint16_t total_length;
	uint16_t packet_id;
	uint16_t fragment_offset;
	uint8_t  time_to_live;
	uint8_t  next_proto_id;
	uint16_t hdr_checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} __attribute__((__packed__));

// Common part of TCP and UDP headers
struct os_net_tcpudp_header
{
	uint16_t src_port;
	uint16_t dst_port;
} __attribute__((__packed__));

// Get a packet's ethernet header
static inline bool os_net_get_ether_header(struct os_net_packet* packet, struct os_net_ether_header** out_ether_header)
{
	// For now we only support Ethernet packets, so this cannot fail.
	*out_ether_header = (struct os_net_ether_header*) (*((uint8_t**)(packet)) + packet->_reserved1);
	return true;
}

// Get a packet's IPv4 header given its ethernet header
static inline bool os_net_get_ipv4_header(struct os_net_ether_header* ether_header, struct os_net_ipv4_header** out_ipv4_header)
{
	// if we return false this may be 1 past the end of the array, which is legal in C
	*out_ipv4_header = (struct os_net_ipv4_header*) ((char*) ether_header + sizeof(struct os_net_ether_header));
	return ether_header->ether_type == (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ? 0x0008 : 0x0800);
}

// Get a packet's TCP/UDP common header given its IPv4 header
static inline bool os_net_get_tcpudp_header(struct os_net_ipv4_header* ipv4_header, struct os_net_tcpudp_header** out_tcpudp_header)
{
	// if we return false this may be 1 past the end of the array, which is legal in C
	*out_tcpudp_header = (struct os_net_tcpudp_header*) ((char*) ipv4_header + sizeof(struct os_net_ipv4_header));
	bool result = (ipv4_header->next_proto_id == 6 /* TCP */) | (ipv4_header->next_proto_id == 17 /* UDP */);
	// TODO: Remove; Dirty trick to force the compiler to emit a single branch for both conditions, halving the number of paths in symbex
	return *((volatile bool*)&result);
}


// Compute the checksum of an IPv4 packet
static inline bool os_net_ipv4_checksum_valid(struct os_net_ipv4_header* header)
{
	(void) header;
	return true; // TODO
}