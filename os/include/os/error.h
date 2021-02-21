#pragma once

#ifndef OS_DEBUG_LEVEL
#define OS_DEBUG_LEVEL 0
#endif


// Causes the entire application to exit.
_Noreturn void os_exit(void);


#if DEBUG_LEVEL > 0
void os_debug(const char* message);
#else
static inline void os_debug(const char* message)
{
	(void) message;
	// Nothing.
}
#endif

_Noreturn static inline void os_fatal(const char* message)
{
	os_debug(message);
	os_exit();
}
