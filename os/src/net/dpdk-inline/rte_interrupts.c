#include <rte_interrupts.h>


int rte_intr_enable(const struct rte_intr_handle* intr_handle)
{
	(void) intr_handle;

	// OS ASSUMPTION: No interrupts
	return 0;
}
