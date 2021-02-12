#include "os/debug.h"

#ifdef DEBUG_LEVEL
#include <stdarg.h>
#include <stdio.h>

void os_debug(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	fflush(stderr);
	va_end(args);
}
#endif
