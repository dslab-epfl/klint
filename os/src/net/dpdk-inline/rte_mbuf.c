#include <rte_mbuf.h>

#include <rte_lcore.h>

#include "os/fail.h"
#include "os/memory.h"
#include "structs/buffer_pool.h"


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

	pool->size = n;
	pool->populated_size = n;
	pool->elt_size = data_room_size + sizeof(struct rte_mbuf);
	pool->ops_index = 0;

	struct buffer_pool* buffer_pool = buffer_pool_create(n, pool->elt_size);
	uint8_t* buffers = (uint8_t*) os_memory_alloc(n, pool->elt_size);
//	uintptr_t phys_addr = os_memory_virt_to_phys(buffers);

	for (size_t i = 0; i < n; i++) {
		struct rte_mbuf* buf = (struct rte_mbuf*) (buffers + i * pool->elt_size);
		// TODO: find a way to infer at least buf_addr/buf_iova/buf_len ; maybe by making buf_iova an uninterpreted function and inferring it holds...
		buf->refcnt = 1;
		buf->pool = pool;
		buf->nb_segs = 1;
		buf->port = MBUF_INVALID_PORT;
		buf->data_off = sizeof(struct rte_mbuf);
		buf->buf_addr = (uint8_t*) buf + buf->data_off;
		buf->buf_iova = os_memory_virt_to_phys(buf->buf_addr); //phys_addr + i * pool->elt_size + buf->data_off;
		buf->buf_len = pool->elt_size - buf->data_off;
	}

	buffer_pool_put(buffer_pool, n, (void*) buffers);
	pool->pool_data = buffer_pool;

	return pool;
}
