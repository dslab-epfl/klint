#ifndef OS_MEMORY_H
#define OS_MEMORY_H

#include <stdint.h>
#include <stddef.h>

//@ #include <list.gh>


// Returns a zero-initialized, previously-unused block that can hold 'count' times 'size'.
// For simplicity, never fails; if there is not enough memory available, crashes the program.
// The 'count == 1' in the contract allows one to avoid having to assume sizeof(struct X) <= SIZE_MAX, which VeriFast otherwise complains about
void* os_memory_init(size_t count, size_t size);
//@ requires count == 1 || count * size <= SIZE_MAX;
//@ ensures chars(result, count * size, ?cs) &*& true == all_eq(cs, 0) &*& result + count * size <= (char *)UINTPTR_MAX;

#endif