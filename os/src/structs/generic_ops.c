#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <nmmintrin.h>

#include "generic_ops.h"

bool generic_eq(void* a, void* b, size_t obj_size)
//@ requires [?f1]chars(a, obj_size, ?ac) &*& [?f2]chars(b, obj_size, ?bc);
//@ ensures [f1]chars(a, obj_size, ac) &*& [f2]chars(b, obj_size, bc) &*& result == (ac == bc);
{
	return 0 == memcmp(a, b, obj_size);
}

hash_t generic_hash(void* obj, size_t obj_size)
//@ requires [?f]chars(obj, obj_size, ?value);
/*@ ensures [f]chars(obj, obj_size, value) &*&
            result == hash_fp(value); @*/
{
	// Without these two VeriFast loses track of the original obj and obj_size
	//@ void* old_obj = obj;
	//@ size_t old_obj_size = obj_size;
	
	//@ size_t discarded_size = 0;
	uint32_t hash = 0;
	while (obj_size >= 8)
	/*@ invariant [f]chars(obj - discarded_size, discarded_size, _) &*&
	              [f]chars(obj, obj_size, _) &*&
	              old_obj == obj - discarded_size &*&
	              old_obj_size == obj_size + discarded_size; @*/
	{
		//@ chars_limits(obj);
		//@ chars_split(obj, 8);
		//@ chars_to_integer_(obj, 8, false);
		hash = (uint32_t) _mm_crc32_u64(hash, *((uint64_t*)obj));
		//@ integer__to_chars(obj, 8, false);
		//@ discarded_size += 8;
		obj = (void*) (((char*)obj) + 8);
		obj_size -= 8;
	}
	if (obj_size >= 4) {
		//@ chars_limits(obj);
		//@ chars_split(obj, 4);
		//@ chars_to_integer_(obj, 4, false);
		hash = _mm_crc32_u32(hash, *((uint32_t*)obj));
		//@ integer__to_chars(obj, 4, false);
		//@ discarded_size += 4;
		obj = (void*) (((char*)obj) + 4);
		obj_size -= 4;
		//@ chars_join(obj - discarded_size);
	}
	if (obj_size >= 2) {
		//@ chars_limits(obj);
		//@ chars_split(obj, 2);
		//@ chars_to_integer_(obj, 2, false);
		hash = _mm_crc32_u16(hash, *((uint16_t*)obj));
		//@ integer__to_chars(obj, 2, false);
		//@ discarded_size += 2;
		obj = (void*) (((char*)obj) + 2);
		obj_size -= 2;
		//@ chars_join(obj - discarded_size);
	}
	if (obj_size == 1) {
		//@ chars_split(obj, 1);
		//@ chars_to_integer_(obj, 1, false);
		hash = _mm_crc32_u8(hash, *((uint8_t*)obj));
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


void generic_copy(void* src, void* dst, size_t obj_size)
//@ requires [?f]chars(src, obj_size, ?srccs) &*& chars(dst, obj_size, ?dstcs);
//@ ensures [f]chars(src, obj_size, srccs) &*& chars(dst, obj_size, srccs);
{
	memcpy(dst, src, obj_size);
}
