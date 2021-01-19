#include <rte_malloc.h>

#include <stdint.h>

#include "os/fail.h"
#include "os/memory.h"


void* rte_malloc(const char *type, size_t size, unsigned align)
{
	// Easier to share the implementation; not performance-sensitive anyway
	return rte_zmalloc(type, size, align);
}

void* rte_zmalloc(const char* type, size_t size, unsigned align)
{
	(void) type;

	if (align > size) {
		size = align;
	}

	return os_memory_alloc(1, size);
}

void* rte_zmalloc_socket(const char *type, size_t size, unsigned align, int socket)
{
	(void) socket;

	return rte_zmalloc(type, size, align);
}

void* rte_realloc(void* ptr, size_t size, unsigned align)
{
	(void) ptr;
	(void) size;
	(void) align;

	os_fail("rte_realloc is not supported (yet?)");
}

void rte_free(void* ptr)
{
	(void) ptr;
	// No freeing necessary
}

int rte_malloc_heap_socket_is_external(int socket_id)
{
	(void) socket_id;

	// All memory is internal
	return 0;
}
