#pragma once

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif


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
	// Nothing. Ensure the message can be removed from the final binary.
}
#endif
