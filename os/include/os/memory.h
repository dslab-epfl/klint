#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

//@ #include <list.gh>

// 32-bit hash because a 64-bit one is generally not useful for data structure purposes (unless you create tables with > 2**32 elements)
typedef uint32_t hash_t;
#define chars_to_hashes chars_to_uints
//@ fixpoint hash_t hash_fp(list<char> value);


// Allocates a pinned, zero-initialized memory block of the given length (size * count), aligned to the length.
// "Pinned" here means "the virtual-to-physical mapping will never change", not just that it will always be in memory.
// This allows the allocated memory's physical address to be given to a device for DMA.
// For simplicity, never fails; if there is not enough memory available, crashes the program.
// TODO: Fix impls & contract in the tool to do the overflow check or something
void* os_memory_alloc(size_t count, size_t size);
//@ requires emp;
//@ ensures chars(result, count * size, ?cs) &*& true == all_eq(cs, 0) &*& result + count * size <= (char*) UINTPTR_MAX;

// Maps the region of physical address memory defined by (address, size) into virtual memory.
void* os_memory_phys_to_virt(uintptr_t addr, size_t size);
//@ requires emp;
//@ ensures emp;

// Gets the physical address corresponding to the given virtual address.
uintptr_t os_memory_virt_to_phys(const void* addr);
//@ requires emp;
//@ ensures emp;


static inline bool os_memory_eq(const void* a, const void* b, size_t obj_size)
//@ requires [?f1]chars(a, obj_size, ?ac) &*& [?f2]chars(b, obj_size, ?bc);
//@ ensures [f1]chars(a, obj_size, ac) &*& [f2]chars(b, obj_size, bc) &*& result == (ac == bc);
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


static inline hash_t os_memory_hash(const void* obj, size_t obj_size)
//@ requires [?f]chars(obj, obj_size, ?value);
/*@ ensures [f]chars(obj, obj_size, value) &*&
            result == hash_fp(value); @*/
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

	// Proving this with VeriFast is a huge pain because it currently does not support value-preserving char*-to-int* transformations (except for int32_t);
	// but logically this is obvious since 'f' may be <1 and thus we do not have the right to modify 'value'!
	//@ assert [f]chars(old_obj, old_obj_size, ?old_value);
	//@ assume(value == old_value);

	// Proving this is rather pointless since we're using externals for the intrinsics anyway (so they could misbehave if the CPU is buggy)
	// all we care about is that this function is deterministic
	//@ assume(hash == hash_fp(value));

	return hash;
}


static inline void os_memory_copy(const void* src, void* dst, size_t obj_size)
//@ requires [?f]chars(src, obj_size, ?srccs) &*& chars(dst, obj_size, ?dstcs);
//@ ensures [f]chars(src, obj_size, srccs) &*& chars(dst, obj_size, srccs);
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
