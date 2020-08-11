#ifndef GENERIC_OPS_H_INCLUDED
#define GENERIC_OPS_H_INCLUDED

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <nmmintrin.h>


/*@
fixpoint unsigned hash_fp(list<char> lst) {
  switch(lst) {
    case(nil):
      return 0;
    case cons(h,t):
      return h + 17 * hash_fp(t);
  }
}
@*/

static inline bool generic_eq(char* a, char* b, unsigned obj_size)
//@ requires [?f1]chars(a, obj_size, ?ac) &*& [?f2]chars(b, obj_size, ?bc);
//@ ensures [f1]chars(a, obj_size, ac) &*& [f2]chars(b, obj_size, bc) &*& result == (ac == bc);
{
	return 0 == memcmp(a, b, obj_size);
}

static inline unsigned generic_hash(char* obj, unsigned obj_size)
//@ requires [?f1]chars(obj, obj_size, ?value);
//@ ensures [f1]chars(obj, obj_size, value) &*& result == hash_fp(value);
{
	unsigned hash = 0;
	while (obj_size >= 8) {
		hash = _mm_crc32_u64(hash, *((uint64_t*)obj));
		obj += 8;
		obj_size -= 8;
	}
	if (obj_size >= 4) {
		hash = _mm_crc32_u32(hash, *((uint32_t*)obj));
		obj += 4;
		obj_size -= 4;
	}
	if (obj_size >= 2) {
		hash = _mm_crc32_u16(hash, *((uint16_t*)obj));
		obj += 2;
		obj_size -= 2;
	}
	if (obj_size == 1) {
		hash = _mm_crc32_u8(hash, *((uint8_t*)obj));
	}
	return hash;
}

#endif
