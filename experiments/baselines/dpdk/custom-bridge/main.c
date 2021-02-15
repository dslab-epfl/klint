#include "nf.h"

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>


// Just needs to be high enough to not run out of buffers
#define MEMPOOL_BUFFER_COUNT 1024

#if BATCH_SIZE + 0 == 0
#error Please define BATCH_SIZE
#endif

// Can be anything
#define MAX_DEVICES 2

static uint16_t devices_count;
static struct rte_ether_addr device_addrs[MAX_DEVICES];
static struct rte_ether_addr endpoint_addrs[MAX_DEVICES];

static uint16_t bufs_to_tx_count[MAX_DEVICES];
static struct rte_mbuf* bufs_to_tx[MAX_DEVICES][BATCH_SIZE];

static void device_init(unsigned device, struct rte_mempool* mbuf_pool)
{
	int ret;

	struct rte_eth_conf device_conf = {0};
	ret = rte_eth_dev_configure(device, 1, 1, &device_conf);
	if (ret != 0) {
		rte_exit(1, "Couldn't configure device");
	}

	ret = rte_eth_tx_queue_setup(device, 0, 0, rte_eth_dev_socket_id(device), NULL /* default config */);
	if (ret != 0) {
		rte_exit(1, "Couldn't configure a TX queue");
	}

	ret = rte_eth_rx_queue_setup(device, 0, 0, rte_eth_dev_socket_id(device), NULL /* default config */, mbuf_pool);
	if (ret != 0) {
		rte_exit(1, "Couldn't configure an RX queue");
	}

	ret = rte_eth_dev_start(device);
	if (ret != 0) {
		rte_exit(1, "Couldn't start device");
	}

	rte_eth_promiscuous_enable(device);
	if (rte_eth_promiscuous_get(device) != 1) {
		rte_exit(1, "Couldn't set device as promiscuous");
	}

	rte_eth_macaddr_get(device, &(device_addrs[device]));
	// TODO have some configuration for the endpoints
	endpoint_addrs[device] = (struct rte_ether_addr){.addr_bytes = {device}};
}


void tx_packet(struct rte_mbuf* mbuf, uint16_t device)
{
	bufs_to_tx[device][bufs_to_tx_count[device]] = mbuf;
	bufs_to_tx_count[device] = bufs_to_tx_count[device] + 1;
}

void flood_packet(struct rte_mbuf* mbuf)
{
	for (uint16_t device = 0; device < devices_count; device++) {
		if (mbuf->port != device) {
			bufs_to_tx[device][bufs_to_tx_count[device]] = mbuf;
			bufs_to_tx_count[device] = bufs_to_tx_count[device] + 1;
		}
	}
}


int main(int argc, char** argv)
{
	// Initialize DPDK, and change argc/argv to look like nothing happened
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(1, "Error with DPDK init");
	}
	argc -= ret;
	argv += ret;

	devices_count = rte_eth_dev_count_avail();
	if (devices_count == 0) {
		rte_exit(1, "No devices??");
	}
	if (devices_count > MAX_DEVICES) {
		rte_exit(1, "Too many devices, please increase MAX_DEVICES");
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
		rte_exit(1, "Cannot create DPDK pool");
	}

	for (uint16_t device = 0; device < devices_count; device++) {
		device_init(device, mbuf_pool);
	}

	if (!nf_init(devices_count)) {
		rte_exit(1, "Initialization failed.");
	}

	while(1) {
		for (uint16_t device = 0; device < devices_count; device++) {
			struct rte_mbuf* bufs[BATCH_SIZE];
			uint16_t nb_rx = rte_eth_rx_burst(device, 0, bufs, BATCH_SIZE);
			for (int16_t n = 0; n < nb_rx; n++) {
				nf_handle(bufs[n]);
			}
			for (uint16_t out_device = 0; out_device < devices_count; out_device++) {
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
