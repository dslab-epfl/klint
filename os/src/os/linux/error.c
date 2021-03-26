#include "os/error.h"

#include <stdlib.h>


#if DEBUG_LEVEL > 0
#include <stdio.h>

void os_debug(const char* message)
{
	fprintf(stderr, "%s\n", message);
	fflush(stderr);
}
#endif
