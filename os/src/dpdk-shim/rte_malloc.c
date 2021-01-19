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

	uint8_t* result = (uint8_t*) os_memory_alloc(1, size + align);
	if (align != 0) {
		result = result + (align - ((uintptr_t) result % align));
	}
	return (void*) result;
}

void* rte_realloc(void* ptr, size_t size, unsigned align)
{
	(void) ptr;
	(void) size;
	(void) align;

	os_fail("rte_realloc is not supported (yet?)");
	return (void*) 0;
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
