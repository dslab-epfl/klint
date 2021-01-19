#include <rte_errno.h>


RTE_DEFINE_PER_LCORE(int, _rte_errno);


const char* rte_strerror(int errnum)
{
	(void) errnum;

	return "<DPDK error>";
}
