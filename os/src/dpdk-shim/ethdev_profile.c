#include <ethdev_profile.h>

int __rte_eth_dev_profile_init(uint16_t port_id, struct rte_eth_dev* dev)
{
	(void) port_id;
	(void) dev;

	return 0;
}
