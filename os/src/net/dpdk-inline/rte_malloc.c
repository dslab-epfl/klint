#include <rte_malloc.h>

#include <rte_lcore.h>

#include "os/memory.h"


void* rte_zmalloc_socket(const char* type, size_t size, unsigned align, int socket)
{
	(void) type;
	(void) socket;

	if (align > size) {
		size = align;
	}

	return os_memory_alloc(1, size);
}

void* rte_zmalloc(const char* type, size_t size, unsigned align)
{
	return rte_zmalloc_socket(type, size, align, (int) rte_socket_id());
}
