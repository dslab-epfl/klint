#include "os/fail.h"

#include "os/debug.h"

#include <stdlib.h>


_Noreturn void os_fail(const char* message)
{
	(void) message;
	os_debug(message);
	exit(1);
}
