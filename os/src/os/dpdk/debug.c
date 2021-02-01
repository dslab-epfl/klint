#include "os/debug.h"

#ifdef DEBUG
#include <rte_log.h>

void os_debug(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	rte_vlog(RTE_LOG_DEBUG, RTE_LOGTYPE_USER1, format, args);
	va_end(args);
}
#endif
