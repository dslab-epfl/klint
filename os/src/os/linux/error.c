#include "os/error.h"

#include <stdlib.h>


_Noreturn void os_exit(void)
{
	exit(1);
}


#if DEBUG_LEVEL > 1
#include <stdio.h>

void os_debug(const char* message)
{
	fprintf(stderr, "%s\n", message);
	fflush(stderr);
}
#endif
