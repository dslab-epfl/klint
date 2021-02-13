#include <rte_interrupts.h>


// OS ASSUMPTION: No interrupts


int rte_intr_enable(const struct rte_intr_handle* intr_handle)
{
	(void) intr_handle;
	return 0;
}

int rte_intr_disable(const struct rte_intr_handle* intr_handle)
{
	(void) intr_handle;
	return 0;
}

int rte_intr_allow_others(struct rte_intr_handle* intr_handle)
{
	(void) intr_handle;
	return 0;
}

int rte_intr_callback_unregister(const struct rte_intr_handle* intr_handle, rte_intr_callback_fn cb, void* cb_arg)
{
	(void) intr_handle;
	(void) cb;
	(void) cb_arg;
	return 0;
}
