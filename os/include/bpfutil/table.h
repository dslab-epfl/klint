#pragma once

#include <stddef.h>

#include "os/structs/map.h"

struct bpfutil_table {
	size_t key_size;
	size_t value_size;
	void* values;
	struct os_map* map;
};

static inline void bpfutil_table_update(struct bpfutil_table* table, void* key, void* value)
{
	void* unused;
	if (os_map_get(table->map, key, &unused)) {
		os_map_remove(table->map, key);
	}
	os_map_set(table->map, key, value);
}

static inline void* bpfutil_table_lookup(struct bpfutil_table* table, void* key)
{
	void* result;
	if (os_map_get(table->map, key, &result)) {
		return result;
	}
	return NULL;
}

static inline void bpfutil_table_delete(struct bpfutil_table* table, void* key)
{
	os_map_remove(table->map, key);
}


#define BPF_TABLE_hash(key_type, value_type, name, size) \
	static value_type name##_values[size]; \
	static struct os_map* name##_map; \
	static struct bpfutil_table name; \
	__attribute__((constructor)) static void name##_ctor(void) \
	{ \
		name##_map = os_map_alloc(sizeof(key_type), size); \
		name = (struct bpfutil_table) { .key_size = sizeof(key_type), .value_size = sizeof(value_type), .values = name##_values, .map = name##_map }; \
	}

#define BPF_TABLE(type, key_type, value_type, name, size) BPF_TABLE_##type(key_type, value_type, name, size)
