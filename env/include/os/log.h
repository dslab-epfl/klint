#pragma once

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

void os_debug2(unsigned long long int value);
#if DEBUG_LEVEL > 0
// No pre/postconditions, this method needs not be verified
void os_debug(const char* message);
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
