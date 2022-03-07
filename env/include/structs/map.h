#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h> // for SIZE_MAX

//@ #include "proof/ghost_map.gh"


struct map;

//@ predicate mapp(struct map* map, size_t key_size, size_t capacity, list<pair<list<char>, size_t> > values, list<pair<list<char>, void*> > addrs);


// Allocates a map for keys of the given size (in bytes) and integral values (size_t) with the given capacity.
struct map* map_alloc(size_t key_size, size_t capacity);
/*@ requires capacity * 64 <= SIZE_MAX; @*/
/*@ ensures mapp(result, key_size, capacity, nil, nil); @*/
//@ terminates;

// Tries to get the value associated with the given key.
// Returns true iff the key is found, and puts the value in out_value.
// Otherwise, returns false.
bool map_get(struct map* map, void* key_ptr, size_t* out_value);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             key_ptr != NULL &*&
             [?frac]chars(key_ptr, key_size, ?key) &*&
             *out_value |-> _; @*/
/*@ ensures mapp(map, key_size, capacity, values, addrs) &*&
            [frac]chars(key_ptr, key_size, key) &*&
            switch(ghostmap_get(values, key)) {
              case none: return result == false &*& *out_value |-> _;
              case some(v): return result == true &*& *out_value |-> v;
            }; @*/
//@ terminates;

// Sets the value associated with the given key in the map, requiring space to be available and the key to not already be there.
void map_set(struct map* map, void* key_ptr, size_t value);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             key_ptr != NULL &*&
             [0.25]chars(key_ptr, key_size, ?key) &*&
             length(values) < capacity &*&
             ghostmap_get(values, key) == none &*&
             ghostmap_get(addrs, key) == none; @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_set(values, key, value), ghostmap_set(addrs, key, key_ptr)); @*/
//@ terminates;

// Removes the given key from the map.
void map_remove(struct map* map, void* key_ptr);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
             key_ptr != NULL &*&
             [?frac]chars(key_ptr, key_size, ?key) &*&
             frac != 0.0 &*&
             ghostmap_get(values, key) != none &*&
             ghostmap_get(addrs, key) == some(key_ptr); @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_remove(values, key), ghostmap_remove(addrs, key)) &*&
            [frac + 0.25]chars(key_ptr, key_size, key); @*/
//@ terminates;
