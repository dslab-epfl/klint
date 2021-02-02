#include "os/memory.h"

#include <rte_eal_paging.h>
#include <rte_common.h>
#include <rte_malloc.h>

#include "os/fail.h"


size_t os_memory_pagesize(void)
{
	return rte_mem_page_size();
}

void* os_memory_alloc(const size_t count, const size_t size)
{
	// Align must "obviously" be a power of 2 and at least 64, says DPDK doc
	size_t align = rte_align64pow2(count * size);
	if (align < 64) {
		align = 64;
	}
	// Not pinned, but OK because the DPDK "OS" is only used with DPDK net, which uses different methods for pinned memory needed by drivers
	return rte_calloc("os_memory_alloc", count, size, align);
}

void* os_memory_phys_to_virt(const uintptr_t addr, const size_t size)
{
	(void) addr;
	(void) size;

	os_fail("os_memory_phys_to_virt is not supported");
}

uintptr_t os_memory_virt_to_phys(const void* const addr)
{
	// Probably unnecessary but costs nothing to support, the function is right there
	return rte_malloc_virt2iova(addr);
}
