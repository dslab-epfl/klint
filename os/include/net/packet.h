#pragma once

// TODO should have a typdef for 'device_t' or something like that, to avoid the commonly-hardcoded uint16_t

#include <stdbool.h>
#include <stdint.h>

#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

typedef uint8_t net_ether_addr_t[6];

// Packet received on a device
struct net_packet {
	uint8_t* data;
	uint16_t device;
	uint16_t length;
	uint8_t _padding[4];
	void* os_tag; // NFs must not touch this
};

// Ethernet header
struct net_ether_header
{
	net_ether_addr_t dst_addr;
	net_ether_addr_t src_addr;
	uint16_t ether_type;
} __attribute__((__packed__));

// IPv4 header
struct net_ipv4_header
{
	uint8_t  version : 4,
	         ihl : 4;
	uint8_t  type_of_service;
	uint16_t total_length;
	uint16_t packet_id;
	uint16_t fragment_offset;
	uint8_t  time_to_live;
	uint8_t  next_proto_id;
	uint16_t checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} __attribute__((__packed__));

// Common part of TCP and UDP headers
struct net_tcpudp_header
{
	uint16_t src_port;
	uint16_t dst_port;
} __attribute__((__packed__));


// Get a packet's ethernet header
static inline bool net_get_ether_header(struct net_packet* packet, struct net_ether_header** out_ether_header)
{
	// For now we only support Ethernet packets, so this cannot fail.
	*out_ether_header = (struct net_ether_header*) packet->data;
	return true;
}

// Get a packet's IPv4 header given its ethernet header
static inline bool net_get_ipv4_header(struct net_ether_header* ether_header, struct net_ipv4_header** out_ipv4_header)
{
	// if we return false this may be 1 past the end of the array, which is legal in C
	*out_ipv4_header = (struct net_ipv4_header*) (ether_header + 1);
	return ether_header->ether_type == (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ? 0x0008 : 0x0800);
}

// Get a packet's TCP/UDP common header given its IPv4 header
static inline bool net_get_tcpudp_header(struct net_ipv4_header* ipv4_header, struct net_tcpudp_header** out_tcpudp_header)
{
	// if we return false this may be 1 past the end of the array, which is legal in C
	*out_tcpudp_header = (struct net_tcpudp_header*) (ipv4_header + 1);
	return (ipv4_header->next_proto_id == IP_PROTOCOL_TCP) || (ipv4_header->next_proto_id == IP_PROTOCOL_UDP);
}

// Compute the checksum of an IPv4 packet
static inline bool net_ipv4_checksum_valid(struct net_ipv4_header* header)
{
	(void) header;
	return true; // TODO (for the router only so no big deal for now)
}

// Incrementally updates an IP/UDP/TCP checksum given a 16-bit word change
static inline void net_checksum_update(uint16_t* checksum_ptr, uint16_t old_word, uint16_t new_word)
{
	// RFC 1624 Equation 3
	*checksum_ptr = ~(~(*checksum_ptr) + ~old_word + new_word);
}

// Incrementally updates a packet's checksum given its IPv4 header and the old and new values of a 16-bit word, as well as whether the word is in the IP header
static inline void net_packet_checksum_update(struct net_ipv4_header* ipv4_header, uint16_t old_word, uint16_t new_word, bool in_ip)
{
	if (in_ip) {
		// manual pointer addition to avoid an "address of packed member" warning
		net_checksum_update((uint16_t*) ipv4_header + 6, old_word, new_word);
	}

	uint16_t* l4_header = (uint16_t*) (ipv4_header + 1);
	if (ipv4_header->next_proto_id == IP_PROTOCOL_TCP) {
		net_checksum_update(l4_header + 8, old_word, new_word);
	} else if (ipv4_header->next_proto_id == IP_PROTOCOL_UDP) {
		net_checksum_update(l4_header + 3, old_word, new_word);
	}
}
