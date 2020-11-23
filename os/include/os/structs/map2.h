#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h> // for SIZE_MAX

//@ #include "proof/ghost_map.gh"


struct os_map2;

//@ predicate mapp2(struct os_map2* map, size_t key_size, size_t value_size, size_t capacity, list<pair<list<char>, list<char> > > items);


struct os_map2* os_map2_alloc(size_t key_size, size_t value_size, size_t capacity);
/*@ requires key_size > 0 &*&
             key_size * capacity * 2 <= SIZE_MAX &*&
             value_size > 0 &*&
             value_size * capacity * 2 <= SIZE_MAX &*&
             capacity * sizeof(size_t) * 2 <= SIZE_MAX; @*/
/*@ ensures mapp2(result, key_size, value_size, capacity, nil); @*/

bool os_map2_get(struct os_map2* map, void* key_ptr, void* out_value_ptr);
/*@ requires mapp2(map, ?key_size, ?value_size, ?capacity, ?items) &*&
             [?f]chars(key_ptr, key_size, ?key) &*&
             chars(out_value_ptr, value_size, _); @*/
/*@ ensures mapp2(map, key_size, value_size, capacity, items) &*&
            [f]chars(key_ptr, key_size, key) &*&
            switch(ghostmap_get(items, key)) {
              case none: return result == false &*& chars(out_value_ptr, value_size, _);
              case some(v): return result == true &*& chars(out_value_ptr, value_size, v);
            }; @*/

bool os_map2_set(struct os_map2* map, void* key_ptr, void* value_ptr);
/*@ requires mapp2(map, ?key_size, ?value_size, ?capacity, ?items) &*&
             [?kf]chars(key_ptr, key_size, ?key) &*&
             [?vf]chars(value_ptr, value_size, ?value) &*&
             ghostmap_get(items, key) == none; @*/
/*@ ensures [kf]chars(key_ptr, key_size, key) &*&
            [vf]chars(value_ptr, value_size, value) &*&
            length(items) < capacity ? (result == true &*& mapp2(map, key_size, value_size, capacity, ghostmap_set(items, key, value)))
                                     : (result == false &*& mapp2(map, key_size, value_size, capacity, items)); @*/

void os_map2_remove(struct os_map2* map, void* key_ptr);
/*@ requires mapp2(map, ?key_size, ?value_size, ?capacity, ?items) &*&
             [?f]chars(key_ptr, key_size, ?key) &*&
             ghostmap_get(items, key) != none; @*/
/*@ ensures [f]chars(key_ptr, key_size, key) &*&
            mapp2(map, key_size, value_size, capacity, ghostmap_remove(items, key)); @*/
