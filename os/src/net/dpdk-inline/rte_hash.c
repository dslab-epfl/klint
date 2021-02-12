#include <rte_hash.h>

#include <stddef.h>


struct rte_hash* rte_hash_create(const struct rte_hash_parameters* params)
{
	(void) params;
	// Always fail.
	return NULL;
}
