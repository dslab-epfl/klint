#include <rte_memzone.h>

int rte_memzone_free(const struct rte_memzone* mz)
{
	(void) mz;

	// No freeing
	return 0;
}
