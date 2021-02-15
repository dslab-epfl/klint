#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <rte_mbuf.h>


// Packet framework
void tx_packet(struct rte_mbuf* mbuf, uint16_t device);
void flood_packet(struct rte_mbuf* mbuf);

// NF
bool nf_init(uint16_t devices_count, time_t expiration_time, size_t capacity);
void nf_handle(struct rte_mbuf* mbuf, time_t time);
