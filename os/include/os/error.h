#pragma once

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif


// Causes the entire system to stop.
_Noreturn void os_halt(void);
//@ requires emp;
//@ ensures false;


#if DEBUG_LEVEL > 0
void os_debug(const char* message);
//@ requires emp;
//@ ensures emp;
//@ terminates;
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
{
	//@ assume(false); // VeriFast does not support the conditional declaration of os_debug as a prototype or as a static inline function...
	os_debug(message);
	os_halt();
}
