#include <rte_eal_memconfig.h>


void rte_mcfg_mempool_write_lock(void)
{
	// OS ASSUMPTION: Single core
	// Nothing
}

void rte_mcfg_mempool_write_unlock(void)
{
	// OS ASSUMPTION: Single core
	// Nothing
}


void rte_mcfg_tailq_write_lock(void)
{
	// OS ASSUMPTION: Single core
	// Nothing
}

void rte_mcfg_tailq_write_unlock(void)
{
	// OS ASSUMPTION: Single core
	// Nothing
}
