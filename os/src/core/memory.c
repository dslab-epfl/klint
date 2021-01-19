#include "os/memory.h"

#include <stdlib.h>

#include "os/fail.h"


void* os_memory_alloc(uint64_t number, uint64_t size)
{
	void* block = calloc(number, size);
	if (block == NULL) {
		os_fail("Out of memory!");
	}

	return block;
}
