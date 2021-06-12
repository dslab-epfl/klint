#pragma once

#ifndef VERIFAST

_Noreturn static inline void halt(void)
{
	__asm__ volatile("hlt");
	__builtin_unreachable(); // otherwise the compiler complains, because it doesn't know hlt semantics
}

#else
// TODO VeriFast should know about __builtin_unreachable, and maybe even model __asm__ as a terminating ensures-false function...
#include <stdlib.h>
_Noreturn static inline void halt(void)
//@ requires emp;
//@ ensures false;
//@ terminates;
{
	exit(0);
}
#endif
