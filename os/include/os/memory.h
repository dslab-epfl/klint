#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

//@ #include <list.gh>

// A larger hash type than this is generally not useful for data structure purposes
typedef unsigned hash_t;


// Allocates a pinned, zero-initialized memory block of the given length (size * count), aligned to the length.
// "Pinned" here means "the virtual-to-physical mapping will never change", not just that it will always be in memory.
// This allows the allocated memory's physical address to be given to a device for DMA.
// For simplicity, never fails; if there is not enough memory available, crashes the program.
// The contract looks a bit odd to explicitly allow for the 'alloc(1, sizeof(...))' pattern; TODO fix VeriFast to have sizeof(...) <= SIZE_MAX since sizeof is a size_t
void* os_memory_alloc(size_t count, size_t size);
//@ requires count == 1 || count * size <= SIZE_MAX;
//@ ensures chars(result, count * size, ?cs) &*& true == all_eq(cs, 0) &*& result + count * size <= (char*) UINTPTR_MAX;
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
	//@ assume(false); // TODO
	while (obj_size >= sizeof(uint64_t))
	{
		if (*((uint64_t*) a) != *((uint64_t*) b))
		{
			return false;
		}
		obj_size = obj_size - sizeof(uint64_t);
		a = (uint64_t*) a + 1;
		b = (uint64_t*) b + 1;
	}
	if ((obj_size & sizeof(uint32_t)) != 0)
	{
		if (*((uint32_t*) a) != *((uint32_t*) b))
		{
			return false;
		}
		a = (uint32_t*) a + 1;
		b = (uint32_t*) b + 1;
	}
	if ((obj_size & sizeof(uint16_t)) != 0)
	{
		if (*((uint16_t*) a) != *((uint16_t*) b))
		{
			return false;
		}
		a = (uint16_t*) a + 1;
		b = (uint16_t*) b + 1;
	}
	if ((obj_size & sizeof(uint8_t)) != 0)
	{
		if (*((uint8_t*) a) != *((uint8_t*) b))
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
	//@ assume(false); // TODO
	// Without these two VeriFast loses track of the original obj and obj_size
	//@ void* old_obj = obj;
	//@ size_t old_obj_size = obj_size;

	//@ size_t discarded_size = 0;
	hash_t hash = 0;
	while (obj_size >= sizeof(uint32_t))
	/*@ invariant [f]chars(obj - discarded_size, discarded_size, _) &*&
	              [f]chars(obj, obj_size, _) &*&
	              old_obj == obj - discarded_size &*&
	              old_obj_size == obj_size + discarded_size; @*/
	{
		//@ chars_limits(obj);
		//@ chars_split(obj, 4);
		//@ chars_to_integer_(obj, 4, false);
		hash = (hash >> 5) + hash + *((uint32_t*) obj);
		//@ integer__to_chars(obj, 4, false);
		//@ discarded_size += 4;
		obj = (uint32_t*) obj + 1;
		obj_size -= sizeof(uint32_t);
	}
	if ((obj_size & sizeof(uint16_t)) != 0)
	{
		//@ chars_limits(obj);
		//@ chars_split(obj, 2);
		//@ chars_to_integer_(obj, 2, false);
		hash = (hash >> 5) + hash + *((uint16_t*) obj);
		//@ integer__to_chars(obj, 2, false);
		//@ discarded_size += 2;
		obj = (uint16_t*) obj + 1;
		//@ chars_join(obj - discarded_size);
	}
	if ((obj_size & sizeof(uint8_t)) != 0)
	{
		//@ chars_split(obj, 1);
		//@ chars_to_integer_(obj, 1, false);
		hash = (hash >> 5) + hash + *((uint8_t*) obj);
		//@ integer__to_chars(obj, 1, false);
		//@ discarded_size += 1;
		//@ chars_join(obj + 1 - discarded_size);
	}
	return hash;
}


static inline void os_memory_copy(const void* src, void* dst, size_t obj_size)
//@ requires [?f]chars(src, obj_size, ?srccs) &*& chars(dst, obj_size, ?dstcs);
//@ ensures [f]chars(src, obj_size, srccs) &*& chars(dst, obj_size, srccs);
//@ terminates;
{
	//@ assume(false); // TODO
	while (obj_size >= sizeof(uint64_t))
	{
		*((uint64_t*) dst) = *((uint64_t*) src);
		obj_size = obj_size - sizeof(uint64_t);
		src = (uint64_t*) src + 1;
		dst = (uint64_t*) dst + 1;
	}
	if ((obj_size & sizeof(uint32_t)) != 0)
	{
		*((uint32_t*) dst) = *((uint32_t*) src);
		src = (uint32_t*) src + 1;
		dst = (uint32_t*) dst + 1;
	}
	if ((obj_size & sizeof(uint16_t)) != 0)
	{
		*((uint16_t*) dst) = *((uint16_t*) src);
		src = (uint16_t*) src + 1;
		dst = (uint16_t*) dst + 1;
	}
	if ((obj_size & sizeof(uint8_t)) != 0)
	{
		*((uint8_t*) dst) = *((uint8_t*) src);
	}
}
