#pragma once

#include <stddef.h>

#include "compat/linux/types.h"

#include "os/memory.h"
#include "os/structs/map2.h"


enum bpf_map_type {
	BPF_MAP_TYPE_HASH,
//	BPF_MAP_TYPE_ARRAY
// don't care about others for now
};

#define BPF_ANY 0

struct bpf_map_def {
	unsigned int type;
	size_t key_size;
	size_t value_size;
	unsigned int max_entries;
	// The following are not in the original definition; but we use the fact that C initializers don't need to be complete so we can store stuff in the struct itself
	struct os_map2* _map;
	void* _value_holder; // workaround since we cannot gain ownership of values within the map; works as long as code uses one lookup at a time
};

void* bpf_map_lookup_elem(struct bpf_map_def* map, void* key)
{
	// "Perform a lookup in map for an entry associated to key. Return Map value associated to key, or NULL if no entry was found."
	if (os_map2_get(map->_map, key, &(map->_value_holder))) {
		return map->_value_holder;
	}
	return NULL;
}

long bpf_map_update_elem(struct bpf_map_def* map, void* key, void* value, u64 flags)
{
	// "Add or update the value of the entry associated to key in map with value. flags is one of:
	//  BPF_NOEXIST The entry for key must not exist in the map.
	//  BPF_EXIST The entry for key must already exist in the map.
	//  BPF_ANY No condition on the existence of the entry for key.
	//  Flag value BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY  (all elements always exist), the helper would return an error.
	//  Return 0 on success, or a negative error in case of failure."

	// let's just ignore the flags for now, we haven't even defined BPF_NOEXIST so code can't use it, only BPF_ANY
	(void) flags;

	return os_map2_set(map->_map, key, value) ? 0 : -1;
}

long bpf_map_delete_elem(struct bpf_map_def* map, void* key)
{
	// "Delete entry with key from map. Return 0 on success, or a negative error in case of failure."

	// since this is verified code we don't need to assert that the key is already there
	os_map2_remove(map->_map, key);
	return 0;
}

// Not in the Linux definition, necessary for a standard native program
// (we could lazily init in the lookup/update/delete functions but that would slow down processing)
void bpf_map_init(struct bpf_map_def* map)
{
	if (map->type == BPF_MAP_TYPE_HASH) {
		map->_map = os_map2_alloc(map->key_size, map->value_size, map->max_entries);
		map->_value_holder = os_memory_alloc(1, map->value_size);
	}
}
