#pragma once

#include "os/memory.h"

void *memset(void *s, int c, size_t n)
{
	for (size_t a = 0; a < n; a++) {
		((uint8_t*)s)[a] = (uint8_t) c;
	}
}

void *memcpy(void *restrict dest, const void *restrict src, size_t n)
{
	os_memory_copy(src, dest, n);
}
