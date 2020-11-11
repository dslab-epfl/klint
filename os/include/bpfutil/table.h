#pragma once

#include "os/structs/map.h"

struct bpfutil_table {
	size_t key_size;
	size_t value_size;
	void* values;
	struct os_map* map;
};

void bpfutil_table_update(struct bpfutil_table* table, void* key, void* value);

void* bpfutil_table_lookup(struct bpfutil_table* table, void* key);

void bpfutil_table_delete(struct bpfutil_table* table, void* key);


#define BPF_TABLE_hash(key_type, value_type, name, size) \
	static value_type name##_values[size]; \
	static struct os_map* name##_map; \
	static struct bpfutil_table name; \
	__attribute__((constructor)) static void name##_ctor(void) { \
		name##_map = os_map_alloc(sizeof(key_type), size); \
		name = (struct bpfutil_table) { .key_size = sizeof(key_type), .value_size = sizeof(value_type), .values = name##_values, .map = name##_map }; \
	}

#define BPF_TABLE(type, key_type, value_type, name, size) BPF_TABLE_##type(key_type, value_type, name, size)
