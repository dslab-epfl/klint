#include "net/tx.h"

#include <stddef.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "net/skeleton.h"
#include "os/error.h"
#include "os/init.h"


// Just needs to be high enough to not run out of buffers
#define MEMPOOL_BUFFER_COUNT 1024

// We handle the BATCH_SIZE == 1 case specially, but others are subject to DPDK constraints, e.g. not too small
#if BATCH_SIZE + 0 == 0
#error Please define BATCH_SIZE
#endif

#define MAX_DEVICES 2
// TODO properly do refcount shenanigans
_Static_assert(MAX_DEVICES == 2, "see todo");

static device_t devices_count;
static struct rte_ether_addr device_addrs[MAX_DEVICES];
static struct rte_ether_addr endpoint_addrs[MAX_DEVICES];

static uint16_t bufs_to_tx_count[MAX_DEVICES];
static struct rte_mbuf* bufs_to_tx[MAX_DEVICES][BATCH_SIZE];

static void device_init(device_t device, struct rte_mempool* mbuf_pool)
{
	int ret;

	struct rte_eth_conf device_conf = {0};
	ret = rte_eth_dev_configure(device, 1, 1, &device_conf);
	if (ret != 0) {
		os_fatal("Couldn't configure device");
	}

	ret = rte_eth_tx_queue_setup(device, 0, BATCH_SIZE == 1 ? 96 : 0, rte_eth_dev_socket_id(device), NULL /* default config */);
	if (ret != 0) {
		os_fatal("Couldn't configure a TX queue");
	}

	ret = rte_eth_rx_queue_setup(device, 0, BATCH_SIZE == 1 ? 96 : 0, rte_eth_dev_socket_id(device), NULL /* default config */, mbuf_pool);
	if (ret != 0) {
		os_fatal("Couldn't configure an RX queue");
	}

	ret = rte_eth_dev_start(device);
	if (ret != 0) {
		os_fatal("Couldn't start device");
	}

	rte_eth_promiscuous_enable(device);
	if (rte_eth_promiscuous_get(device) != 1) {
		os_fatal("Couldn't set device as promiscuous");
	}

	rte_eth_macaddr_get(device, &(device_addrs[device]));
	// TODO have some configuration for the endpoints
	endpoint_addrs[device] = (struct rte_ether_addr){.addr_bytes = {device}};
}


// TODO make sure we never get multiple net_transmit calls for the same mbuf? or handle it? idk
void net_transmit(struct net_packet* packet, device_t device, enum net_transmit_flags flags)
{
	struct net_ether_header* ether_header = (struct net_ether_header*) packet->data;
	if (flags & UPDATE_ETHER_ADDRS) {
		memcpy(&(ether_header->src_addr), &(device_addrs[device]), sizeof(struct rte_ether_addr));
		memcpy(&(ether_header->dst_addr), &(endpoint_addrs[device]), sizeof(struct rte_ether_addr));
	}

	bufs_to_tx[device][bufs_to_tx_count[device]] = (struct rte_mbuf*) packet->os_tag;
	bufs_to_tx_count[device] = bufs_to_tx_count[device] + 1;
}

void net_flood(struct net_packet* packet)
{
	for (device_t device = 0; device < devices_count; device++) {
		if (packet->device != device) {
			bufs_to_tx[device][bufs_to_tx_count[device]] = (struct rte_mbuf*) packet->os_tag;
			bufs_to_tx_count[device] = bufs_to_tx_count[device] + 1;
		}
	}
}


int main(int argc, char** argv)
{
	// Initialize DPDK, and change argc/argv to look like nothing happened
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		os_fatal("Error with DPDK init");
	}
	argc -= ret;
	argv += ret;

	os_init();

	devices_count = rte_eth_dev_count_avail();
	if (devices_count == 0) {
		os_fatal("No devices??");
	}
	if (devices_count > MAX_DEVICES) {
		os_fatal("Too many devices, please increase MAX_DEVICES");
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
		os_fatal("Cannot create DPDK pool");
	}

	for (device_t device = 0; device < devices_count; device++) {
		device_init(device, mbuf_pool);
	}

	if (!nf_init(devices_count)) {
		os_fatal("Initialization failed.");
	}

	while(1) {
		for (device_t device = 0; device < devices_count; device++) {
			struct rte_mbuf* bufs[BATCH_SIZE];
			uint16_t nb_rx = rte_eth_rx_burst(device, 0, bufs, BATCH_SIZE);
			for (int16_t n = 0; n < nb_rx; n++) {
				struct net_packet packet = {
					.data = (uint8_t*) bufs[n]->buf_addr + bufs[n]->data_off,
					.length = bufs[n]->data_len,
					.device = bufs[n]->port,
					.os_tag = bufs[n]
				};
				nf_handle(&packet);
			}
			for (device_t out_device = 0; out_device < devices_count; out_device++) {
				uint16_t nb_tx = rte_eth_tx_burst(out_device, 0, bufs_to_tx[out_device], bufs_to_tx_count[out_device]);
				for (uint16_t n = nb_tx; n < bufs_to_tx_count[out_device]; n++) {
					rte_pktmbuf_free(bufs_to_tx[out_device][n]);
				}
				bufs_to_tx_count[out_device] = 0;
			}
		}
	}

	return 0;
}
