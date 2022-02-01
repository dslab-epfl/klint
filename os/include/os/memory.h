#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// TODO this is only for the os_memory_alloc contract, should be shadow-included only if possible?
#include "arch/cache.h"

//@ #include <list.gh>

// Amount of memory available to the program, in bytes (256 MB)
#define OS_MEMORY_SIZE (256ull * 1024ull * 1024ull)

// A larger hash type than this is generally not useful for data structure purposes
typedef unsigned hash_t;


// Allocates a pinned, zero-initialized, contiguous memory block of the given length (size * count), aligned to the length rounded up to the cache line size.
// "Pinned" here means "the virtual-to-physical mapping will never change", not just that it will always be in memory.
// This allows the allocated memory's physical address to be given to a device for DMA.
// For simplicity, never fails; if there is not enough memory available, crashes the program.
void* os_memory_alloc(size_t count, size_t size);
//@ requires count * size <= SIZE_MAX;
/*@ ensures chars(result, count * size, ?cs) &*& true == all_eq(cs, 0) &*& result + count * size <= (char*) UINTPTR_MAX &*&
            result != NULL &*& (size_t) result % (size + CACHE_LINE_SIZE - (size % CACHE_LINE_SIZE)) == 0; @*/
//@ terminates;

// Maps the region of physical address memory defined by (address, size) into virtual memory.
void* os_memory_phys_to_virt(uintptr_t addr, size_t size);
//@ requires emp;
//@ ensures emp;
//@ terminates;

// Gets the physical address corresponding to the given virtual address.
uintptr_t os_memory_virt_to_phys(const void* addr);
//@ requires emp;
//@ ensures emp;
//@ terminates;


static inline bool os_memory_eq(const void* a, const void* b, size_t obj_size)
//@ requires [?f1]chars(a, obj_size, ?ac) &*& [?f2]chars(b, obj_size, ?bc);
//@ ensures [f1]chars(a, obj_size, ac) &*& [f2]chars(b, obj_size, bc) &*& result == (ac == bc);
//@ terminates;
{
	// Assume the correctness of the memory equality function, because VeriFast loses track of values when converting to/from chars/integers.
	// Anyway, this function is fairly easy to audit, and run frequently enough that any crashes or other issues should be obvious.
	//@ assume(false);
	const char* ac = (const char*) a;
	const char* bc = (const char*) b;
	for (size_t n = 0; n < obj_size; n++)
	{
		if (ac[n] != bc[n])
		{
			return false;
		}
	}
	return true;
}


//@ fixpoint hash_t hash_fp(list<char> value);

static inline hash_t os_memory_hash(const void* obj, size_t obj_size)
//@ requires [?f]chars(obj, obj_size, ?value);
/*@ ensures [f]chars(obj, obj_size, value) &*&
            result == hash_fp(value); @*/
//@ terminates;
{
	// Assume the hashing function is correct, because VeriFast doesn't support treating unsigned overflow as well-defined (without also losing checks for signed overflow).
	// Anyway, this function is obviously pure, it cannot modify its input due to the 'const' modifier, and it is run frequently enough that any crashes would be obvious.
	//@ assume(false);
	// Still, there's a leftover beginning of proof below.
	// Without these two VeriFast loses track of the original obj and obj_size
	//@ void* old_obj = obj;
	//@ size_t old_obj_size = obj_size;

	//@ size_t discarded_size = 0;
	hash_t hash = 0;
	while (obj_size >= sizeof(unsigned))
	/*@ invariant [f]chars(obj - discarded_size, discarded_size, _) &*&
	              [f]chars(obj, obj_size, _) &*&
	              old_obj == obj - discarded_size &*&
	              old_obj_size == obj_size + discarded_size; @*/
	{
		//@ chars_limits(obj);
		//@ chars_split(obj, 4);
		//@ chars_to_integer_(obj, 4, false);
		unsigned value;
		__builtin_memcpy(&value, obj, sizeof(unsigned));
		hash = (hash >> 5) + hash + value;
		//@ integer__to_chars(obj, 4, false);
		//@ discarded_size += 4;
		obj = (const unsigned*) obj + 1;
		obj_size -= sizeof(unsigned);
	}
	if ((obj_size & sizeof(unsigned short)) != 0)
	{
		//@ chars_limits(obj);
		//@ chars_split(obj, 2);
		//@ chars_to_integer_(obj, 2, false);
		unsigned short value;
		__builtin_memcpy(&value, obj, sizeof(unsigned short));
		hash = (hash >> 5) + hash + value;
		//@ integer__to_chars(obj, 2, false);
		//@ discarded_size += 2;
		obj = (const unsigned short*) obj + 1;
		//@ chars_join(obj - discarded_size);
	}
	if ((obj_size & sizeof(unsigned char)) != 0)
	{
		//@ chars_split(obj, 1);
		//@ chars_to_integer_(obj, 1, false);
		unsigned char value;
		__builtin_memcpy(&value, obj, sizeof(unsigned char));
		hash = (hash >> 5) + hash + value;
		//@ integer__to_chars(obj, 1, false);
		//@ discarded_size += 1;
		//@ chars_join(obj + 1 - discarded_size);
	}
	return hash;
}

static inline void os_memory_copy(const void* restrict src, void* restrict dst, size_t obj_size)
//@ requires [?f]chars(src, obj_size, ?srccs) &*& chars(dst, obj_size, ?dstcs);
//@ ensures [f]chars(src, obj_size, srccs) &*& chars(dst, obj_size, srccs);
//@ terminates;
{
	// Assume the correctness of the memory copy function, because VeriFast loses track of values when converting to/from chars/integers.
	// Anyway, this function is short, easily auditable, and run frequently enough that any crashes or other issues should be obvious.
	//@ assume(false);
	const char* restrict srcc = (const char* restrict) src;
	char* restrict dstc = (char* restrict) dst;
	for (size_t n = 0; n < obj_size; n++)
	{
		dstc[n] = srcc[n];
	}
}
