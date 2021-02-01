#pragma once

#include <stdint.h>
#include <stddef.h>

//@ #include <list.gh>


// Allocates a pinned, zero-initialized memory block of the given length (size * count), aligned to the length.
// "Pinned" here means "the virtual-to-physical mapping will never change", not just that it will always be in memory.
// This allows the allocated memory's physical address to be given to a device for DMA.
// For simplicity, never fails; if there is not enough memory available, crashes the program.
// (The 'count == 1' in the contract allows one to avoid having to assume sizeof(struct X) <= SIZE_MAX, which VeriFast otherwise complains about)
// (TODO: Fix VeriFast)
void* os_memory_alloc(size_t count, size_t size);
//@ requires count == 1 || count * size <= SIZE_MAX;
//@ ensures chars(result, count * size, ?cs) &*& true == all_eq(cs, 0) &*& result + count * size <= (char*) UINTPTR_MAX;

// TODO is this necessary? currently it's there for dpdk-inline but might not be needed after all
// Get the page size.
size_t os_memory_pagesize(void);
//@ requires true;
//@ ensures true;

// Maps the region of physical address memory defined by (address, size) into virtual memory.
void* os_memory_phys_to_virt(uintptr_t addr, size_t size);
//@ requires true;
//@ ensures true;

// Gets the physical address corresponding to the given virtual address.
uintptr_t os_memory_virt_to_phys(const void* addr);
//@ requires true;
//@ ensures true;
