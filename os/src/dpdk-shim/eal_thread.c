#include <rte_lcore.h>


// OS ASSUMPTION: Single thread
RTE_DEFINE_PER_LCORE(unsigned int, _lcore_id) = 0;

unsigned rte_socket_id(void)
{
	// OS ASSUMPTION: Single socket
	return 0;
}
