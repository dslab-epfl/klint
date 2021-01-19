#include "os/debug.h"

// Bit tricky - we may have DEBUG undefined in the OS but defined in the NF, so we must undef it to define the function
#ifdef os_debug
#define os_debug_
#undef os_debug
#endif

#ifdef DEBUG
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
#else
void os_debug(const char* format, ...)
{
	// Nothing
	(void) format;
}
#endif

#ifdef os_debug_
#define os_debug(...)
#undef os_debug_
#endif
