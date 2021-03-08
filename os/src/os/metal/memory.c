#include "os/memory.h"

#include "os/error.h"


static uint8_t memory[0x1000000]; // 256 MB should be enough?
static size_t memory_used_len;


void* os_memory_alloc(size_t count, size_t size)
{
	// Cannot overflow, guaranteed by the contract
	const size_t full_size = size * count;

	// Weird but valid; return a likely-invalid address for debugging convenience
	if (full_size == 0) {
		return memory + sizeof(memory);
	}

	// Align as required by the contract
	const size_t align_diff = (size_t) (memory + memory_used_len) % full_size;
	if (align_diff != 0) {
		memory_used_len = memory_used_len + (full_size - align_diff);
	}

	if (sizeof(memory) - memory_used_len < full_size) {
		os_fatal("Not enough space left to allocate");
	}

	void* result = memory + memory_used_len;
	memory_used_len = memory_used_len + full_size;
	return result;
}

void* os_memory_phys_to_virt(uintptr_t addr, size_t size)
{
	// phys == virt, no protections
	(void) size;
	return (void*) addr;
}

uintptr_t os_memory_virt_to_phys(const void* addr)
{
	// phys == virt
	return (uintptr_t) addr;
}
