#include "os/network.h"
#include "private/network.h"

#include <stddef.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#include "fail.h"


// --- Private stuff ---

// DPDK constants; keep the same values as Vigor for now
#define RX_QUEUE_SIZE 96
#define TX_QUEUE_SIZE 96
#define MEMPOOL_BUFFER_COUNT 256

// change at will...
#define MAX_DEVICES 10

uint16_t devices_count;
struct rte_ether_addr device_addrs[MAX_DEVICES];
struct rte_ether_addr endpoint_addrs[MAX_DEVICES];


static void os_net_init_device(unsigned device, struct rte_mempool* mbuf_pool)
{
	int ret;

	struct rte_eth_conf device_conf = {0};
	ret = rte_eth_dev_configure(device, 1, 1, &device_conf);
	if (ret != 0) {
		fail("Couldn't configure device %u: %d", device, ret);
	}

	ret = rte_eth_tx_queue_setup(device, 0, TX_QUEUE_SIZE, rte_eth_dev_socket_id(device), NULL /* default config */);
	if (ret != 0) {
		fail("Couldn't configure a TX queue for device %u: %d", device, ret);
	}

	ret = rte_eth_rx_queue_setup(device, 0, RX_QUEUE_SIZE, rte_eth_dev_socket_id(device), NULL /* default config */, mbuf_pool);
	if (ret != 0) {
		fail("Couldn't configure an RX queue for device %u: %d", device, ret);
	}

	ret = rte_eth_dev_start(device);
	if (ret != 0) {
		fail("Couldn't start device %u: %d", device, ret);
	}

	rte_eth_promiscuous_enable(device);
	if (rte_eth_promiscuous_get(device) != 1) {
		fail("Couldn't set device %u as promiscuous", device);
	}

	rte_eth_macaddr_get(device, &(device_addrs[device]));
	// TODO have some configuration for the endpoints
	endpoint_addrs[device] = (struct rte_ether_addr){.addr_bytes = {device}};
}



// --- Internal APIs ---

int os_net_init(int argc, char** argv)
{
	// Initialize DPDK, and change argc/argv to look like nothing happened
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		fail("Error with DPDK init: %d", ret);
	}
	devices_count = rte_eth_dev_count_avail();
	if (devices_count > MAX_DEVICES) {
		fail("Too many devices, please increase MAX_DEVICES");
	}
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
		"MEMPOOL", // name
		MEMPOOL_BUFFER_COUNT * devices_count, // #elements
		0, // cache size (per-lcore, not useful in a single-threaded app)
		0, // application private area size
		RTE_MBUF_DEFAULT_BUF_SIZE, // data buffer size
		rte_socket_id() // socket ID
	);
	if (mbuf_pool == NULL) {
		fail("Cannot create DPDK pool: %s", rte_strerror(rte_errno));
	}
	for (uint16_t device = 0; device < devices_count; device++) {
		os_net_init_device(device, mbuf_pool);
	}
	return ret;
}

uint16_t os_net_devices_count(void)
{
	return rte_eth_dev_count_avail();
}

struct os_net_packet* os_net_receive(uint16_t device)
{
	struct rte_mbuf* bufs[1];
	if (rte_eth_rx_burst(device, 0, bufs, 1)) {
		return (struct os_net_packet*) bufs[0];
	}
	return NULL;
}

void os_net_cleanup(struct os_net_packet* packet)
{
	rte_pktmbuf_free((struct rte_mbuf*) packet);
}



// --- Public APIs ---

// TODO: Offload checksums to the hardware if possible
void os_net_transmit(struct os_net_packet* packet, uint16_t device,
                     struct os_net_ether_header* ether_header,
                     struct os_net_ipv4_header* ipv4_header,
                     struct os_net_tcpudp_header* tcpudp_header)
{
	if (ether_header != NULL) {
		memcpy(&(ether_header->src_addr), &(device_addrs[device]), sizeof(struct rte_ether_addr));
		memcpy(&(ether_header->dst_addr), &(endpoint_addrs[device]), sizeof(struct rte_ether_addr));
	}

	if (ipv4_header != NULL) {
		ipv4_header->hdr_checksum = 0; // Assumed by checksum calculation
		ipv4_header->hdr_checksum = rte_ipv4_cksum((void*) ipv4_header);

		if (tcpudp_header != NULL) {
			if (ipv4_header->next_proto_id == IPPROTO_TCP) {
				struct rte_tcp_hdr *tcp_header = (struct rte_tcp_hdr*) tcpudp_header;
				tcp_header->cksum = 0; // Assumed by checksum calculation
				tcp_header->cksum = rte_ipv4_udptcp_cksum((void*) ipv4_header, tcp_header);
			} else if(ipv4_header->next_proto_id == IPPROTO_UDP) {
				struct rte_udp_hdr *udp_header = (struct rte_udp_hdr*) tcpudp_header;
				udp_header->dgram_cksum = 0; // Assumed by checksum calculation
				udp_header->dgram_cksum = rte_ipv4_udptcp_cksum((void*) ipv4_header, udp_header);
			}
		}
	}

	// TODO: avoid refcnt shenanigans if we can...
	rte_mbuf_refcnt_set((struct rte_mbuf*) packet, 2);
	if (rte_eth_tx_burst(device, 0, (struct rte_mbuf**) &packet, 1) == 0) {
		fail("DPDK failed to send");
	}
}

void os_net_flood(struct os_net_packet* packet)
{
	rte_mbuf_refcnt_set((struct rte_mbuf*) packet, devices_count);
	for (uint16_t device = 0; device < devices_count; device++) {
		if (device != packet->device) {
			if (rte_eth_tx_burst(device, 0, (struct rte_mbuf**) &packet, 1) == 0) {
				fail("DPDK failed to send");
			}
		}
	}
}
