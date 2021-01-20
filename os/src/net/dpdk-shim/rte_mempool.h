#pragma once

// DPDK depends on these transitive include
#include <rte_atomic.h>
#include <rte_lcore.h>

#include <rte_common.h>

#include "os/fail.h"


struct rte_mempool {
	size_t elt_size;
	size_t private_data_size;
	const char* name;
};

static inline struct rte_mempool* rte_mempool_create_empty(const char* name, unsigned n, unsigned elt_size, unsigned cache_size, unsigned private_data_size, int socket_id, unsigned flags)
{
	// TODO
}

static inline int rte_mempool_populate_default(struct rte_mempool* mp)
{
	// TODO
}

static inline rte_iova_t rte_mempool_virt2iova(const void* elt)
{
	// TODO
}

static inline void* rte_mempool_get_priv(struct rte_mempool* mp)
{
	// TODO
}

static inline void rte_mempool_put_bulk(struct rte_mempool* mp, void* const* obj_table, unsigned int n)
{
	// TODO
}

static inline void rte_mempool_put(struct rte_mempool* mp, void* obj)
{
	rte_mempool_put_bulk(mp, &obj, 1);
}

static inline int rte_mempool_get_bulk(struct rte_mempool *mp, void **obj_table, unsigned int n)
{
	// TODO
}

static inline int rte_mempool_get(struct rte_mempool* mp, void** obj_p)
{
	return rte_mempool_get_bulk(mp, obj_p, 1);
}

static inline void rte_mempool_free(struct rte_mempool *mp)
{
	// TODO
}


static inline uint32_t rte_mempool_obj_iter(struct rte_mempool* mp, void* obj_cb, void* obj_cb_arg)
{
	os_fail("rte_mempool_obj_iter is not supported");
}

static inline int rte_mempool_set_ops_byname(struct rte_mempool* mp, const char* name, void* pool_config)
{
	os_fail("rte_mempool_set_ops_byname is not supported");
}
/*
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
*/
