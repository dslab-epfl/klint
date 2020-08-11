#ifndef MAP_H_INCLUDED
#define MAP_H_INCLUDED

#include <stdbool.h>
#include <stdint.h>

//@ #include "proof/ghost_map.gh"

struct os_map;

//@ predicate mapp(struct os_map* map, uint64_t key_size, uint64_t capacity, list<pair<list<char>, uint64_t> > values, list<pair<void*, list<char> > > addrs);


struct os_map* os_map_init(uint64_t key_size, uint64_t capacity);
/*@ requires 0 < capacity &*&
             0 < key_size; @*/
/*@ ensures result == 0 ? true : mapp(result, key_size, capacity, nil, nil); @*/

bool os_map_get(struct os_map* map, void* key_ptr, uint64_t* value_out);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             chars(key_ptr, key_size, ?key) &*&
             *value_out |-> _; @*/
/*@ ensures mapp(map, key_size, capacity, values, addrs) &*&
            chars(key_ptr, key_size, key) &*&
            switch(ghostmap_get(values, key)) {
              case none: return result == false &*& *value_out |-> _;
              case some(v): return result == true &*& *value_out |-> v;
            }; @*/

void os_map_set(struct os_map* map, void* key_ptr, uint64_t value);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             [0.25]chars(key_ptr, key_size, ?key) &*&
             length(values) < capacity &*&
             ghostmap_get(values, key) == none; @*/
/*@ ensures mapp(map, key_size, capacity, ?new_values, ?new_addrs) &*&
            new_values == ghostmap_set(values, key, value) &*&
            new_addrs == ghostmap_set(addrs, key_ptr, key); @*/

void os_map_remove(struct os_map* map, void* key_ptr);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             [?frac]chars(key_ptr, key_size, ?key) &*&
             frac != 0.0 &*&
             ghostmap_get(addrs, key_ptr) == some(?key2); @*/
/*@ ensures mapp(map, key_size, capacity, ?new_values, ?new_addrs) &*&
            new_values == ghostmap_remove(values, key) &*&
            new_addrs == ghostmap_remove(addrs, key_ptr) &*&
           [frac + 0.25]chars(key_ptr, key_size, key); @*/

#endif
