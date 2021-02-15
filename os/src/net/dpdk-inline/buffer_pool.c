#include "structs/buffer_pool.h"

#include "os/memory.h"


struct buffer_pool
{
	void** buffers;
	size_t size;
};


struct buffer_pool* buffer_pool_create(size_t count, size_t size)
{
	struct buffer_pool* pool = (struct buffer_pool*) os_memory_alloc(1, sizeof(struct buffer_pool));
	pool->buffers = os_memory_alloc(count, size);
	pool->size = size;
	return pool;
}

bool buffer_pool_take(struct buffer_pool* pool, size_t count, void** out_buffers)
{
	if (pool->size < count) {
		return false;
	}

	pool->size = pool->size - count;
	for (size_t n = 0; n < count; n++) {
		out_buffers[n] = pool->buffers[pool->size + n];
	}

	return true;
}

bool buffer_pool_put(struct buffer_pool* pool, size_t count, void** buffers)
{
	if (SIZE_MAX - count < pool->size) {
		return false;
	}

	for (size_t n = 0; n < count; n++) {
		pool->buffers[pool->size + n] = buffers[n];
	}
	pool->size = pool->size + count;

	return true;
}
