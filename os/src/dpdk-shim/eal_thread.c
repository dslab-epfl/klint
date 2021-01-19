#include <rte_lcore.h>


RTE_DEFINE_PER_LCORE(unsigned int, _lcore_id) = 0;

unsigned rte_socket_id(void)
{
	return 0;
}
