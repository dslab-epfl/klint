#pragma once

#include "arch/halt.h"


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
	// Nothing.
}
#endif

_Noreturn static inline void os_fatal(const char* message)
{
	os_debug(message);
	// On OSes like Linux this will crash instead since hlt cannot be used in user space... which is fine! We want to stop, by any means!
	halt();
}
