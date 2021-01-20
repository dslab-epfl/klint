#include "os/fail.h"

void __rte_panic(const char *funcname, const char *format, ...)
{
	(void) format;

	os_fail(funcname);
}
