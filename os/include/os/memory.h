#pragma once

#include <stdint.h>


// Returns a zero-initialized, previously-unused block that can hold 'count' times 'size'.
// For simplicity, never fails; if there is not enough memory available, crashes the program.
void* os_memory_init(uint64_t count, uint64_t size);
