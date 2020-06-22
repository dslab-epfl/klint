#include "os/memory.h"

#include <stdlib.h>

#include "fail.h"


void* os_memory_init(uint64_t number, uint64_t size)
{
	void* block = calloc(number, size);
	if (block == NULL) {
		fail("Out of memory!");
	}

	return block;
}
