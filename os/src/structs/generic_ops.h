#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t hash_t;
#define chars_to_hashes chars_to_uints

//@ fixpoint hash_t hash_fp(list<char> value);

bool generic_eq(void* a, void* b, size_t obj_size);
//@ requires [?f1]chars(a, obj_size, ?ac) &*& [?f2]chars(b, obj_size, ?bc);
//@ ensures [f1]chars(a, obj_size, ac) &*& [f2]chars(b, obj_size, bc) &*& result == (ac == bc);


hash_t generic_hash(void* obj, size_t obj_size);
//@ requires [?f]chars(obj, obj_size, ?value);
/*@ ensures [f]chars(obj, obj_size, value) &*&
            result == hash_fp(value); @*/

void generic_copy(void* src, void* dst, size_t obj_size);
//@ requires [?f]chars(src, obj_size, ?srccs) &*& chars(dst, obj_size, ?dstcs);
//@ ensures [f]chars(src, obj_size, srccs) &*& chars(dst, obj_size, srccs);
