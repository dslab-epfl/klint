#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h> // for SIZE_MAX

struct map;

/**
 * @brief Allocates a map for keys of the given size (in bytes) and with values for a given size in bytes with the given capacity.
 *
 *
 * @param key_size
 * @param value_size
 * @param capacity
 * @return struct map*
 */
struct map* map_alloc(size_t key_size, size_t value_size, size_t capacity);

/**
 * @brief Tries to get the value associated with the given key
 *
 * @param map
 * @param key_ptr
 * @param out_value
 * @return true when key is found
 * @return false when key is not found
 */
bool map_get(struct map* map, void* key_ptr, void* out_value);

/**
 * @brief Sets the value associated with the given key in the map.
 * if the key is already present in the map, the value associated with the key will be overwritten.
 *
 * The map will not take ownership of either the key or value, rather it will copy their content to memory space owned by the map.
 *
 *
 * @pre map must have available space to add the key value pair
 *
 * @param map
 * @param key_ptr
 * @param value
 */
void map_set(struct map* map, void* key_ptr, void* value);

/**
 * @brief attempts to remove a given key from the map if that key is present in the map
 *
 * @post the memory space used to hold the key and value in the lpm will be made available to hold new key value pair.
 *
 * @param map
 * @param key_ptr
 * @return true the key was in the map and was removed
 * @return false the key was not in the map
 */
bool map_remove(struct map* map, void* key_ptr);