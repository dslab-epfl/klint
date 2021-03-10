#include "os/error.h"

#include <stdbool.h>


_Noreturn void os_halt(void)
{
	while (true) {
		// Nothing
	}
}


#if DEBUG_LEVEL > 0
void os_debug(const char* message)
{
	(void) message;
	// Nothing for now; TODO maybe do something?
}
#endif
