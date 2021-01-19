#include <rte_memory.h>

#include "os/memory.h"


rte_iova_t rte_mem_virt2iova(const void* virt)
{
	return os_memory_virt_to_phys(virt);
}

struct rte_memseg* rte_mem_virt2memseg(const void* virt, const struct rte_memseg_list* msl)
{
	(void) virt;
	(void) msl;

	// No memsegs
	return (void*) 0;
}

int rte_memseg_list_walk(rte_memseg_list_walk_t func, void* arg)
{
	(void) func;
	(void) arg;

	// No memsegs
	return 0;
}
