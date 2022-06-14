#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h> // for SIZE_MAX

//@ #include "proof/ghost_map.gh"

/**
 * @brief holds the structure of a map with key value pairs note that the value is always of type size_t
 */
struct map;

//@ predicate mapp(struct map* map, size_t key_size, size_t capacity, list<pair<list<char>, size_t> > values, list<pair<list<char>, void*> > addrs);

/**
 * @brief Allocates a map for keys of the given size (in bytes) and integral values (size_t) with the given capacity.
 *
 * @param key_size argument that defines the size of the key used in the map
 * @param capacity argument that defines the maximum number of key,pair value the map can take
 * @return struct map*
 */
struct map* map_alloc(size_t key_size, size_t capacity);
/*@ requires capacity * 64 <= SIZE_MAX; @*/
/*@ ensures mapp(result, key_size, capacity, nil, nil); @*/
//@ terminates;

/**
 * @brief Tries to get the value associated with the given key.
 *
 * @pre The key_ptr cannot be NULL
 *
 * @param map the map the key will be searched in
 * @param key_ptr pointer to the key
 * @param out_value pointer that will be set to the value associated with the key if that said key is present in the map
 * @return true key was found
 * @return false key was not found
 */
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

/**
 * @brief Sets the value associated with the given key in the map, requiring space to be available and the key to not already be there.
 *
 * @pre key_ptr cannot be null
 * @pre number of key value pair in the map is not greater than the capacity
 * @pre key_ptr does not already exist in the map
 *
 * @post partial ownership of the key_ptr is passed to the map
 *
 * @param map pointer to the map
 * @param key_ptr pointer to the key that will be added to the map
 * @param value value that will be associated with the key added to the map
 */
void map_set(struct map* map, void* key_ptr, size_t value);
/*@ requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
	     key_ptr != NULL &*&
	     [0.25]chars(key_ptr, key_size, ?key) &*&
	     length(values) < capacity &*&
	     ghostmap_get(values, key) == none &*&
	     ghostmap_get(addrs, key) == none; @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_set(values, key, value), ghostmap_set(addrs, key, key_ptr)); @*/
//@ terminates;

/**
 * @brief removes a given key from the map
 *
 * @pre key_ptr is not NULL
 * @pre key_ptr exists in the map
 *
 * @post ownership of the key_ptr by the map is returned
 *
 * @param map pointer to the map
 * @param key_ptr key to be removed from the map
 */
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
