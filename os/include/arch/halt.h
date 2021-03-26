#pragma once


_Noreturn static inline void halt(void)
{
	__asm__ volatile("hlt");
	__builtin_unreachable(); // otherwise the compiler complains, because it doesn't know hlt semantics
}
