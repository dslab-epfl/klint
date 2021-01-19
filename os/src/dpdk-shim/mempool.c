#include <rte_mbuf_pool_ops.h>
#include <rte_mempool.h>

#include "os/fail.h"
#include "os/memory.h"


#define MAX_POOLS 32
#define MAX_ITEMS_PER_POOL 2048


struct pool {
	void** data;
	unsigned count;
};

static struct pool all_pools[MAX_POOLS];
static size_t pool_index;


static int pool_alloc(struct rte_mempool* mp)
{
	if (pool_index == MAX_POOLS) {
		os_fail("Too many pools");
	}

	struct pool* p = &(all_pools[pool_index]);
	p->data = os_memory_alloc(MAX_ITEMS_PER_POOL, sizeof(void*));

	pool_index = pool_index + 1;
	mp->pool_data = p;
	return 0;
}

static int pool_enqueue(struct rte_mempool* mp, void* const* obj_table, unsigned n)
{
	struct pool* p = (struct pool*) mp->pool_data;

	if (p->count + n >= MAX_ITEMS_PER_POOL) {
		return -ENOBUFS;
	}

	for (unsigned i = 0; i < n; i++) {
		p->data[p->count + i] = obj_table[i];
	}

	p->count = p->count + n;

	return 0;
}

static int pool_dequeue(struct rte_mempool* mp, void** obj_table, unsigned int n)
{
	struct pool* p = (struct pool*) mp->pool_data;

	if (p->count < n) {
		return -ENOBUFS;
	}

	for (unsigned i = 0; i < n; i++) {
		obj_table[i] = p->data[p->count - 1 - i];
	}

	p->count = p->count - n;

	return 0;
}

static unsigned pool_get_count(const struct rte_mempool* mp)
{
	struct pool* p = (struct pool*) mp->pool_data;

	return p->count;
}

static void pool_free(struct rte_mempool* mp)
{
	(void) mp;

	// Nothing.
}

static struct rte_mempool_ops ops = {
	.name = RTE_MBUF_DEFAULT_MEMPOOL_OPS,
	.alloc = pool_alloc,
	.free = pool_free,
	.enqueue = pool_enqueue,
	.dequeue = pool_dequeue,
	.get_count = pool_get_count
};

MEMPOOL_REGISTER_OPS(ops);
