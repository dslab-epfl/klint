#pragma once

#include <stddef.h>

#include "os/memory.h"
#include "os/structs/map2.h"

struct bpfutil_table {
	void* value_holder; // silly hack, will work as long as bpf programs don't reuse results from previous gets
	struct os_map2* map;
};

static inline void bpfutil_table_update(struct bpfutil_table table, void* key, void* value)
{
	void* unused;
	if (os_map2_get(table.map, key, &unused)) {
		os_map2_remove(table.map, key);
	}
	os_map2_set(table.map, key, value);
}

static inline void* bpfutil_table_lookup(struct bpfutil_table table, void* key)
{
	if (os_map2_get(table.map, key, table.value_holder)) {
		return table.value_holder;
	}
	return NULL;
}

static inline void bpfutil_table_delete(struct bpfutil_table table, void* key)
{
	os_map2_remove(table.map, key);
}


#define BPF_TABLE_hash(key_type, value_type, name, size) \
	struct bpfutil_table name; \
	__attribute__((constructor)) static void name##_ctor(void) \
	{ \
		name = (struct bpfutil_table) { .value_holder = os_memory_alloc(1, sizeof(value_type)), .map = os_map2_alloc(sizeof(key_type), sizeof(value_type), size) }; \
	}

#define BPF_TABLE(type, key_type, value_type, name, size) BPF_TABLE_##type(key_type, value_type, name, size)
