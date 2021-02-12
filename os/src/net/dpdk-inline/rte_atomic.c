#include <rte_atomic.h>


void rte_io_rmb(void)
{
	rte_compiler_barrier();
}

void rte_io_wmb(void)
{
	rte_compiler_barrier();
}
