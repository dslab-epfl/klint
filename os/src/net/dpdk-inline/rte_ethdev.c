#include <rte_ethdev.h>

#include <rte_lcore.h>

#include "os/fail.h"
#include "os/memory.h"

// can be anything, we only need 2 * RX+TX for now
#define MAX_MEMZONES 4

static struct rte_memzone memzones[MAX_MEMZONES];
static size_t memzones_count;


int rte_eth_dev_configure(uint16_t port_id, uint16_t nb_rx_q, uint16_t nb_tx_q, const struct rte_eth_conf* dev_conf)
{
	if (nb_rx_q > RTE_MAX_QUEUES_PER_PORT) {
		os_fail("Too many RX queues");
	}

	if (nb_tx_q > RTE_MAX_QUEUES_PER_PORT) {
		os_fail("Too many TX queues");
	}

	struct rte_eth_conf zero_conf = {0};
	if (!os_memory_eq(&zero_conf, dev_conf, sizeof(struct rte_eth_conf))) {
		os_fail("Unsupported device configuration");
	}

	struct rte_eth_dev* dev = &(rte_eth_devices[port_id]);
	if (dev->data->rx_queues != (void**) 0) {
		os_fail("Device was already configured");
	}
	if (dev->data->dev_started != 0) {
		os_fail("Device has already started");
	}

	struct rte_eth_dev_info dev_info;
	if ((*dev->dev_ops->dev_infos_get)(dev, &dev_info) != 0) {
		os_fail("Could not get device info");
	}
	if (nb_rx_q > dev_info.max_rx_queues) {
		os_fail("Too many RX queues for device");
	}
	if (nb_tx_q > dev_info.max_tx_queues) {
		os_fail("Too many TX queues for device");
	}

	dev->data->rx_queues = os_memory_alloc(nb_rx_q, sizeof(void*));
	dev->data->tx_queues = os_memory_alloc(nb_tx_q, sizeof(void*));

	// DPDK does this, not sure if it's useful
	dev->data->dev_conf.rxmode.max_rx_pkt_len = RTE_ETHER_MAX_LEN;

	return 0;
}

int rte_eth_tx_queue_setup(uint16_t port_id, uint16_t tx_queue_id, uint16_t nb_tx_desc, unsigned int socket_id, const struct rte_eth_txconf* tx_conf)
{
	if (nb_tx_desc != 0) {
		os_fail("Unsupported number of TX descs");
	}

	if (socket_id != rte_socket_id()) {
		os_fail("Unsupported socket ID");
	}

	if (tx_conf != (struct rte_eth_txconf*) 0) {
		os_fail("Unsupported TX config");
	}

	struct rte_eth_dev* dev = &(rte_eth_devices[port_id]);
	if (dev->data->tx_queues == (void**) 0) {
		os_fail("Device was not configured yet");
	}
	if (dev->data->dev_started != 0) {
		os_fail("Device has already started");
	}

	struct rte_eth_dev_info dev_info;
	if ((*dev->dev_ops->dev_infos_get)(dev, &dev_info) != 0) {
		os_fail("Could not get device info");
	}

	nb_tx_desc = dev_info.default_txportconf.ring_size;
	if (nb_tx_desc == 0) {
		nb_tx_desc = RTE_ETH_DEV_FALLBACK_TX_RINGSIZE;
	}

	return (*dev->dev_ops->tx_queue_setup)(dev, tx_queue_id, nb_tx_desc, socket_id, &(dev_info.default_txconf));
}


int rte_eth_rx_queue_setup(uint16_t port_id, uint16_t rx_queue_id, uint16_t nb_rx_desc, unsigned int socket_id, const struct rte_eth_rxconf* rx_conf, struct rte_mempool* mp)
{
	if (nb_rx_desc != 0) {
		os_fail("Unsupported number of RX descs");
	}

	if (socket_id != rte_socket_id()) {
		os_fail("Unsupported socket ID");
	}

	if (rx_conf != (struct rte_eth_rxconf*) 0) {
		os_fail("Unsupported RX config");
	}

	struct rte_eth_dev* dev = &(rte_eth_devices[port_id]);
	if (dev->data->rx_queues == (void**) 0) {
		os_fail("Device was not configured yet");
	}
	if (dev->data->dev_started != 0) {
		os_fail("Device has already started");
	}

	struct rte_eth_dev_info dev_info;
	if ((*dev->dev_ops->dev_infos_get)(dev, &dev_info) != 0) {
		os_fail("Could not get device info");
	}

	nb_rx_desc = dev_info.default_rxportconf.ring_size;
	if (nb_rx_desc == 0) {
		nb_rx_desc = RTE_ETH_DEV_FALLBACK_RX_RINGSIZE;
	}

	return (*dev->dev_ops->rx_queue_setup)(dev, rx_queue_id, nb_rx_desc, socket_id, &(dev_info.default_rxconf), mp);
}

int rte_eth_dev_start(uint16_t port_id)
{
	struct rte_eth_dev* dev = &(rte_eth_devices[port_id]);
	if (dev->data->rx_queues == (void**) 0) {
		os_fail("Device was not configured");
	}
	if (dev->data->dev_started != 0) {
		os_fail("Device has already started");
	}

	int result = (*dev->dev_ops->dev_start)(dev);
	if (result != 0) {
		os_fail("Could not start device");
	}

	dev->data->dev_started = 1;
	return 0;
}

int rte_eth_promiscuous_enable(uint16_t port_id)
{
	struct rte_eth_dev* dev = &(rte_eth_devices[port_id]);
	if (dev->data->promiscuous == 1) {
		return 0;
	}

	int result = (*dev->dev_ops->promiscuous_enable)(dev);
	if (result != 0) {
		os_fail("Could not make promiscuous");
	}

	dev->data->promiscuous = 1;
	return 0;
}

int rte_eth_promiscuous_get(uint16_t port_id)
{
	struct rte_eth_dev* dev = &(rte_eth_devices[port_id]);
	return dev->data->promiscuous;
}

int rte_eth_macaddr_get(uint16_t port_id, struct rte_ether_addr* mac_addr)
{
	struct rte_eth_dev* dev = &(rte_eth_devices[port_id]);
	os_memory_copy(&(dev->data->mac_addrs[0]), mac_addr, sizeof(struct rte_ether_addr));
	return 0;
}

int rte_eth_dev_socket_id(uint16_t port_id)
{
	(void) port_id;

	// OS ASSUMPTION: Single core
	return (int) rte_socket_id();
}

const struct rte_memzone* rte_eth_dma_zone_reserve(const struct rte_eth_dev* dev, const char* ring_name, uint16_t queue_id, size_t size, unsigned align, int socket_id)
{
	(void) dev;
	(void) ring_name;
	(void) queue_id;
	(void) align;

	if (memzones_count == MAX_MEMZONES) {
		os_fail("Too many memzones");
	}

	if ((unsigned) socket_id != rte_socket_id()) {
		os_fail("Bad socket ID");
	}

	struct rte_memzone* zone = &(memzones[memzones_count]);
	memzones_count = memzones_count + 1;

	// TODO this size without explicit count here is likely going to be a problem... it's accessed as a ring :/
	zone->addr = os_memory_alloc(1, size);
	zone->phys_addr = os_memory_virt_to_phys(zone->addr);
	zone->len = size;

	return zone;
}
