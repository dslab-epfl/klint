#include "os/error.h"

#include <rte_debug.h>


_Noreturn void os_exit(void)
{
	rte_panic("os_exit");
}

#if DEBUG_LEVEL > 0
#include <rte_log.h>

void os_debug(const char* message)
{
	rte_vlog(RTE_LOG_DEBUG, RTE_LOGTYPE_USER1, "%s\n", message);
}
#endif
