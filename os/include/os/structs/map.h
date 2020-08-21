#ifndef MAP_H_INCLUDED
#define MAP_H_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h> // VeriFast has SIZE_MAX in stdint

//@ #include "proof/ghost_map.gh"


struct os_map;

//@ predicate mapp(struct os_map* map, size_t key_size, size_t capacity, list<pair<list<char>, void*> > values, list<pair<list<char>, void*> > addrs);


struct os_map* os_map_alloc(size_t key_size, size_t capacity);
/*@ requires 0 < capacity &*& capacity <= (SIZE_MAX / 8) &*&
             (capacity & (capacity - 1)) == 0; @*/
/*@ ensures mapp(result, key_size, capacity, nil, nil); @*/

bool os_map_get(struct os_map* map, void* key_ptr, void** out_value);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             chars(key_ptr, key_size, ?key) &*&
             *out_value |-> _; @*/
/*@ ensures mapp(map, key_size, capacity, values, addrs) &*&
            chars(key_ptr, key_size, key) &*&
            switch(ghostmap_get(values, key)) {
              case none: return result == false &*& *out_value |-> _;
              case some(v): return result == true &*& *out_value |-> v;
            }; @*/

void os_map_set(struct os_map* map, void* key_ptr, void* value);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             [0.25]chars(key_ptr, key_size, ?key) &*&
             length(values) < capacity &*&
             ghostmap_get(values, key) == none &*&
             ghostmap_get(addrs, key) == none; @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_set(values, key, value), ghostmap_set(addrs, key, key_ptr)); @*/

void os_map_remove(struct os_map* map, void* key_ptr);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             [?frac]chars(key_ptr, key_size, ?key) &*&
             frac != 0.0 &*&
             ghostmap_get(values, key) != none &*&
             ghostmap_get(addrs, key) == some(key_ptr); @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_remove(values, key), ghostmap_remove(addrs, key)) &*&
           [frac + 0.25]chars(key_ptr, key_size, key); @*/

#endif
