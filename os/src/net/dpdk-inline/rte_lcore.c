#include <rte_lcore.h>


unsigned int rte_socket_id(void)
{
	// OS ASSUMPTION: Single core
	return 0;
}
