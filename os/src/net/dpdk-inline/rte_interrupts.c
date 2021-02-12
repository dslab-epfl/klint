#include <rte_interrupts.h>

/*
int rte_intr_callback_register(const struct rte_intr_handle* intr_handle, rte_intr_callback_fn cb, void* cb_arg)
{
	(void) intr_handle;
	(void) cb;
	(void) cb_arg;

	// OS ASSUMPTION: No interrupts
	return 0;
}
*/
int rte_intr_enable(const struct rte_intr_handle* intr_handle)
{
	(void) intr_handle;

	// OS ASSUMPTION: No interrupts
	return 0;
}
