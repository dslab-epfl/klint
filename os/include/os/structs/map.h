#ifndef MAP_H_INCLUDED
#define MAP_H_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

//@ #include "proof/ghost_map.gh"

struct os_map;

//@ predicate mapp(struct os_map* map, size_t key_size, size_t capacity, list<pair<list<char>, uint64_t> > values, list<pair<list<char>, char*> > addrs);


struct os_map* os_map_init(size_t key_size, size_t capacity);
/*@ requires capacity < (SIZE_MAX / 8) &*&
             key_size > 0; @*/
/*@ ensures result == NULL ? true : mapp(result, key_size, capacity, nil, nil); @*/

bool os_map_get(struct os_map* map, char* key_ptr, uint64_t* value_out);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             chars(key_ptr, key_size, ?key) &*&
             *value_out |-> _; @*/
/*@ ensures mapp(map, key_size, capacity, values, addrs) &*&
            chars(key_ptr, key_size, key) &*&
            switch(ghostmap_get(values, key)) {
              case none: return result == false &*& *value_out |-> _;
              case some(v): return result == true &*& *value_out |-> v;
            }; @*/

void os_map_set(struct os_map* map, char* key_ptr, uint64_t value);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             [0.25]chars(key_ptr, key_size, ?key) &*&
             length(values) < capacity &*&
             ghostmap_get(values, key) == none &*&
             ghostmap_get(addrs, key) == none; @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_set(values, key, value), ghostmap_set(addrs, key, key_ptr)); @*/

void os_map_remove(struct os_map* map, char* key_ptr);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             [?frac]chars(key_ptr, key_size, ?key) &*&
             frac != 0.0 &*&
             ghostmap_get(values, key) != none &*&
             ghostmap_get(addrs, key) == some(key_ptr); @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_remove(values, key), ghostmap_remove(addrs, key)) &*&
           [frac + 0.25]chars(key_ptr, key_size, key); @*/

#endif
