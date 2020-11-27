#pragma once

#include <stddef.h>
#include <stdint.h>

#include "compat/string.h"

#include "os/clock.h"
#include "os/memory.h"
#include "os/structs/map.h"
#include "os/structs/map2.h"
#include "os/structs/pool.h"


// not the best place but they have to be somewhere so...
#define __be16 uint16_t
#define __be32 uint32_t
#define __be64 uint64_t
#define __u8 uint8_t
#define __u16 uint16_t
#define __u32 uint32_t
#define __u64 uint64_t
#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

// See compat/skeleton/xdp.h
#define XDP_DROP -1
#define XDP_TX -2
#define XDP_PASS -3

struct xdp_md {
// CHANGED from uint32_t to uintptr_t since we can't guarantee pointers will fit into 32 bits, unlike in BPF
	uintptr_t data;
	uintptr_t data_end;
// TODO necessary?
//	uint32_t data_meta;
	uint32_t ingress_ifindex;
//	uint32_t rx_queue_index;
//	uint32_t egress_ifindex;
};

// just ignore this for now... but use the arguments to avoid triggering "unused parameter" warnings
#define bpf_csum_diff(r1, from_size, r3, to_size, seed) 0 * r1 * from_size * (uintptr_t)r3 * to_size * seed

static inline long bpf_xdp_adjust_head(struct xdp_md* xdp_md, int delta)
{
	if (delta >= 0) {
		xdp_md->data += delta;
	} else {
		ptrdiff_t old_length = xdp_md->data_end - xdp_md->data;
		uint8_t* new_data = os_memory_alloc(1, old_length - delta);
		memcpy(new_data - delta, (uint8_t*) xdp_md->data, old_length);
		xdp_md->data = (uintptr_t) new_data;
		xdp_md->data_end = (uintptr_t) new_data + old_length - delta;
	}
	return 0;
}

static inline long bpf_xdp_adjust_tail(struct xdp_md* xdp_md, int delta)
{
	if (delta >= 0) {
		xdp_md->data_end -= delta;
	} else {
		ptrdiff_t old_length = xdp_md->data_end - xdp_md->data;
		uint8_t* new_data = os_memory_alloc(1, old_length - delta);
		memcpy(new_data, (uint8_t*) xdp_md->data, old_length);
		xdp_md->data = (uintptr_t) new_data;
		xdp_md->data_end = (uintptr_t) new_data + old_length - delta;
	}
	return 0;
}

// single threaded
#define bpf_get_smp_processor_id() 0

#define bpf_ktime_get_ns os_clock_time
#define bpf_ktime_get_boot_ns os_clock_time

enum bpf_map_type {
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_ARRAY_OF_MAPS, // not actually supported at runtime; but Katran refers to it
	BPF_MAP_TYPE_DEVMAP, // special case, only usable with the redirect function
// don't care about others for now
};

// only supported bpf_map_def flags
#define NO_FLAGS 0

// This should be in bpf_helpers.h, but having it here is much more convenient
struct bpf_map_def {
	uint32_t type;
	size_t key_size;
	size_t value_size;
	size_t max_entries;
	uint32_t map_flags;
	// The following are not in the original definition; but we use the fact that C initializers don't need to be complete so we can store stuff in the struct itself
	struct os_map2* _map; // for _HASH
	struct os_map* _raw_map; // for _LRU_HASH
	struct os_pool* _pool; // for _LRU_HASH
	time_t _counter; // for _LRU_HASH
	uint8_t* _keys; // for _LRU_HASH
	uint8_t* _values; // for _ARRAY and _LRU_HASH
	void* _value_holder; // workaround since we cannot gain ownership of values within the map; works as long as code uses one lookup at a time
};

// no need for typed stuff; but declare a struct because this macro is used with a ; at the end and that's illegal on its own
#define BPF_ANNOTATE_KV_PAIR(name, ...) struct name##_annotate { uint64_t unused; }

// only supported bpf_map_update_elem flags
#define BPF_ANY 0


static inline long bpf_redirect_map(struct bpf_map_def* map, uint32_t key, uint64_t flags)
{
	(void) map;
	(void) flags;

	// Special case, the key is really the port to redirect to
	return key;
}

static inline void* bpf_map_lookup_elem(struct bpf_map_def* map, void* key)
{
	// "Perform a lookup in map for an entry associated to key. Return Map value associated to key, or NULL if no entry was found."
	switch (map->type) {
		case BPF_MAP_TYPE_HASH: {
			if (os_map2_get(map->_map, key, map->_value_holder)) {
				return map->_value_holder;
			}
			return NULL;
		}
		case BPF_MAP_TYPE_ARRAY: {
			size_t index = *((size_t*) key);
			if (index < map->max_entries) {
				memcpy(map->_value_holder, map->_values + (index * map->value_size), map->value_size);
				return map->_value_holder;
			}
			return NULL;
		}
		case BPF_MAP_TYPE_LRU_HASH: {
			map->_counter++;
			size_t index;
			if (os_map_get(map->_raw_map, key, (void*) &index)) {
				memcpy(map->_value_holder, map->_values + (index * map->value_size), map->value_size);
				return map->_value_holder;
			}
			return NULL;
		}
	}
	return NULL;
}

static inline long bpf_map_update_elem(struct bpf_map_def* map, void* key, void* value, uint64_t flags)
{
	// "Add or update the value of the entry associated to key in map with value. flags is one of:
	//  BPF_NOEXIST The entry for key must not exist in the map.
	//  BPF_EXIST The entry for key must already exist in the map.
	//  BPF_ANY No condition on the existence of the entry for key.
	//  Flag value BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY  (all elements always exist), the helper would return an error.
	//  Return 0 on success, or a negative error in case of failure."

	// let's just ignore the flags for now, we haven't even defined BPF_NOEXIST so code can't use it, only BPF_ANY
	(void) flags;

	switch (map->type) {
		case BPF_MAP_TYPE_HASH: {
			// equivalent to set ? 0 : -1, but lower number of paths in case the expression is ignored
			return 1 - os_map2_set(map->_map, key, value);
		}
		case BPF_MAP_TYPE_ARRAY: {
			size_t index = *((size_t*) key);
			if (index < map->max_entries) {
				memcpy(map->_values + (index * map->value_size), value, map->value_size);
				return 0;
			}
			return -1;
		}
		case BPF_MAP_TYPE_LRU_HASH: {
			map->_counter++;
			size_t index;
			if (os_pool_expire(map->_pool, map->_counter, (void*) &index)) {
				os_map_remove(map->_raw_map, map->_keys + (index * map->key_size));
			}
			if (!os_pool_borrow(map->_pool, map->_counter, (void*) &index)) {
				return -1;
			}
			memcpy(map->_keys + (index * map->key_size), key, map->key_size);
			memcpy(map->_values + (index * map->value_size), value, map->value_size);
			return 0;
		}
	}
	return -1;
}

static inline long bpf_map_delete_elem(struct bpf_map_def* map, void* key)
{
	// "Delete entry with key from map. Return 0 on success, or a negative error in case of failure."

	// since this is verified code we don't need to assert that the key is already there
	switch (map->type) {
		case BPF_MAP_TYPE_HASH: {
			os_map2_remove(map->_map, key);
			return 0;
		}
		case BPF_MAP_TYPE_ARRAY: {
			// does not make sense
			return -1;
		}
		case BPF_MAP_TYPE_LRU_HASH: {
			size_t index;
			if (os_map_get(map->_raw_map, key, (void*) &index)) {
				os_pool_return(map->_pool, index);
				os_map_remove(map->_raw_map, map->_keys + (index * map->key_size));
				return 0;
			}
			return -1;
		}
	}
	return -1;
}


// Not in the Linux definition, necessary for a standard native program
// (we could lazily init in the lookup/update/delete functions but that would slow down processing)
static inline void bpf_map_init(struct bpf_map_def* map)
{
	// Single-threaded so no need to specially handle PERCPU
	if (map->type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		map->type = BPF_MAP_TYPE_ARRAY;
	}

	switch (map->type) {
		case BPF_MAP_TYPE_HASH:
			map->_map = os_map2_alloc(map->key_size, map->value_size, map->max_entries);
			break;
		case BPF_MAP_TYPE_ARRAY:
			map->_values = os_memory_alloc(map->max_entries, map->value_size);
			break;
		case BPF_MAP_TYPE_LRU_HASH:
			map->_raw_map = os_map_alloc(map->key_size, map->max_entries);
			map->_pool = os_pool_alloc(map->max_entries);
			map->_keys = os_memory_alloc(map->max_entries, map->key_size);
			map->_values = os_memory_alloc(map->max_entries, map->value_size);
			break;
	}
	map->_value_holder = os_memory_alloc(1, map->value_size);
}
