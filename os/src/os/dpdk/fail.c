#include "os/fail.h"

#include <rte_debug.h>


_Noreturn void os_fail(const char* message)
{
	__rte_panic("os_fail", "%s", message);
}
