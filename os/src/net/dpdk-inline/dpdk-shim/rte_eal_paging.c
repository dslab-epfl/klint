#include <rte_eal_paging.h>

#include "os/memory.h"


size_t rte_mem_page_size(void)
{
	return os_memory_pagesize();
}
