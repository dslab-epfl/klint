#include <rte_malloc.h>

#include "os/memory.h"


void* rte_zmalloc(const char* type, size_t size, unsigned align)
{
	(void) type;

	if (align > size) {
		size = align;
	}

	return os_memory_alloc(1, size);
}
