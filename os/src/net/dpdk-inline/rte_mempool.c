#include <rte_mbuf.h>

#include <rte_lcore.h>

#include "os/fail.h"


// Could be anything
#define MAX_POOLS 1

static struct rte_mempool pools[MAX_POOLS];
static size_t pools_count;


struct rte_mempool* rte_pktmbuf_pool_create(const char *name, unsigned n, unsigned cache_size, uint16_t priv_size, uint16_t data_room_size, int socket_id)
{
	if (cache_size != 0) {
		os_fail("Unsupported cache size");
	}
	if (priv_size != 0) {
		os_fail("Unsupported priv size");
	}
	if ((unsigned) socket_id != rte_socket_id()) {
		os_fail("Unsupported socket ID");
	}

	(void) name; // don't care

	if (pools_count == MAX_POOLS) {
		os_fail("Too many pools");
	}

	struct rte_mempool* pool = &(pools[pools_count]);
	pools_count = pools_count + 1;

// TODO:	pool->pool_data = ???
	pool->size = n;
	pool->populated_size = n;
	pool->elt_size = data_room_size;

	return pool;
}
