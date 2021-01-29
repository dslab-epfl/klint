#include "net/tx.h"

#include <stddef.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "os/fail.h"
#include "net/skeleton.h"


// DPDK constants; keep the same values as Vigor for now
#define RX_QUEUE_SIZE 96
#define TX_QUEUE_SIZE 96
#define MEMPOOL_BUFFER_COUNT 256

// change at will...
#define MAX_DEVICES 10

uint16_t devices_count;
struct rte_ether_addr device_addrs[MAX_DEVICES];
struct rte_ether_addr endpoint_addrs[MAX_DEVICES];


static void device_init(unsigned device, struct rte_mempool* mbuf_pool)
{
	int ret;

	struct rte_eth_conf device_conf = {0};
	ret = rte_eth_dev_configure(device, 1, 1, &device_conf);
	if (ret != 0) {
		os_fail("Couldn't configure device");
	}

	ret = rte_eth_tx_queue_setup(device, 0, TX_QUEUE_SIZE, rte_eth_dev_socket_id(device), NULL /* default config */);
	if (ret != 0) {
		os_fail("Couldn't configure a TX queue");
	}

	ret = rte_eth_rx_queue_setup(device, 0, RX_QUEUE_SIZE, rte_eth_dev_socket_id(device), NULL /* default config */, mbuf_pool);
	if (ret != 0) {
		os_fail("Couldn't configure an RX queue");
	}

	ret = rte_eth_dev_start(device);
	if (ret != 0) {
		os_fail("Couldn't start device");
	}

	rte_eth_promiscuous_enable(device);
	if (rte_eth_promiscuous_get(device) != 1) {
		os_fail("Couldn't set device as promiscuous");
	}

	rte_eth_macaddr_get(device, &(device_addrs[device]));
	// TODO have some configuration for the endpoints
	endpoint_addrs[device] = (struct rte_ether_addr){.addr_bytes = {device}};
}


void net_transmit(struct net_packet* packet, uint16_t device, enum net_transmit_flags flags)
{
	struct net_ether_header* ether_header = (struct net_ether_header*) packet->data;
	if (flags & UPDATE_ETHER_ADDRS) {
		memcpy(&(ether_header->src_addr), &(device_addrs[device]), sizeof(struct rte_ether_addr));
		memcpy(&(ether_header->dst_addr), &(endpoint_addrs[device]), sizeof(struct rte_ether_addr));
	}

	// TODO: avoid refcnt shenanigans...
	rte_mbuf_refcnt_set((struct rte_mbuf*) packet, 2);
	if (rte_eth_tx_burst(device, 0, (struct rte_mbuf**) &packet, 1) == 0) {
		os_fail("DPDK failed to send");
	}
}

void net_flood(struct net_packet* packet)
{
	rte_mbuf_refcnt_set((struct rte_mbuf*) packet, devices_count);
	for (uint16_t device = 0; device < devices_count; device++) {
		if (device != packet->device) {
			if (rte_eth_tx_burst(device, 0, (struct rte_mbuf**) &packet, 1) == 0) {
				os_fail("DPDK failed to send");
			}
		}
	}
}


int main(int argc, char** argv)
{
	// Initialize DPDK, and change argc/argv to look like nothing happened
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		os_fail("Error with DPDK init");
	}
	argc -= ret;
	argv += ret;

	devices_count = rte_eth_dev_count_avail();
	if (devices_count > MAX_DEVICES) {
		os_fail("Too many devices, please increase MAX_DEVICES");
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
		os_fail("Cannot create DPDK pool");
	}

	for (uint16_t device = 0; device < devices_count; device++) {
		device_init(device, mbuf_pool);
	}

	if (!nf_init(devices_count)) {
		os_fail("Initialization failed.");
	}

	while(1) {
		for (uint16_t device = 0; device < devices_count; device++) {
			struct rte_mbuf* bufs[1];
			if (rte_eth_rx_burst(device, 0, bufs, 1)) {
				nf_handle((struct net_packet*) bufs[0]);
				rte_pktmbuf_free(bufs[0]);
			}
		}
	}

	return 0;
}
