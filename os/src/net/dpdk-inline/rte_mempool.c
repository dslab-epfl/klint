#include <rte_mempool.h>

#include "structs/buffer_pool.h"


// Defined as extern by rte_mempool.h
struct rte_mempool_ops_table rte_mempool_ops_table;


static int mempool_enqueue(struct rte_mempool* pool, void*const* obj_table, unsigned n)
{
	return buffer_pool_put((struct buffer_pool*) pool->pool_data, obj_table, (size_t) n) ? 1 : 0;
}

static int mempool_dequeue(struct rte_mempool* pool, void** obj_table, unsigned n)
{
	return buffer_pool_take((struct buffer_pool*) pool->pool_data, obj_table, (size_t) n) ? 1 : 0;
}

__attribute__((constructor))
static void mempool_init(void)
{
	rte_mempool_ops_table.num_ops = 1;
	rte_mempool_ops_table.ops[0].enqueue = mempool_enqueue;
	rte_mempool_ops_table.ops[0].dequeue = mempool_dequeue;
}
