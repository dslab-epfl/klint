#pragma once

#include "net/packet.h"


// Transmit the given packet on the given device
// Precondition: tcpudp_header != NULL  -->  ipv4_header != NULL
// TODO: would be nice to get rid of NULL here :/
void os_net_transmit(struct os_net_packet* packet, uint16_t device,
                     struct os_net_ether_header* ether_header, // if not NULL, MAC addrs are updated
                     struct os_net_ipv4_header* ipv4_header, // if not NULL, IPv4 checksum is recomputed
                     struct os_net_tcpudp_header* tcpudp_header); // if not NULL, TCP/UDP checksum is recomputed

// Transmit the given packet unmodified to all devices except the packet's own
void os_net_flood(struct os_net_packet* packet);
