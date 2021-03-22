#pragma once

#ifndef OS_DEBUG_LEVEL
#define OS_DEBUG_LEVEL 0
#endif


// Causes the entire system to stop.
_Noreturn void os_halt(void);
//@ requires emp;
//@ ensures false;
//@ terminates;


#if DEBUG_LEVEL > 0
void os_debug(const char* message);
#else
static inline void os_debug(const char* message)
//@ requires emp;
//@ ensures emp;
//@ terminates;
{
	(void) message;
	// Nothing.
}
#endif

_Noreturn static inline void os_fatal(const char* message)
//@ requires emp;
//@ ensures false;
//@ terminates;
{
	os_debug(message);
	os_halt();
}
