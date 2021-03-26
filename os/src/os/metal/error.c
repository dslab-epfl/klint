#include "os/error.h"

#include <stdbool.h>


#if DEBUG_LEVEL > 0
void os_debug(const char* message)
//@ requires emp;
//@ ensures emp;
//@ terminates;
{
	(void) message;
	// Nothing for now; TODO maybe do something?
}
#endif
