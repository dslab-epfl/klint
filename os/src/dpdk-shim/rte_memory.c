#include <rte_memory.h>

#include "os/memory.h"


rte_iova_t rte_mem_virt2iova(const void* virt)
{
	return os_memory_virt_to_phys(virt);
}
