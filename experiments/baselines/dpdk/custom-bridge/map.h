#pragma once

#include <stddef.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_table.h>
#include <rte_table_hash.h>
#include <rte_table_hash_func.h>


struct map_value
{
	size_t index;
	uint16_t device;
	uint8_t _padding[6];
};

struct map
{
	struct rte_ether_addr* addrs;
	void* rte_map;
};

static uint64_t key_mask = 0x0000FFFFFFFFFFFFull;

static inline struct map* map_alloc(size_t capacity)
{
	struct map* map = rte_zmalloc("map", sizeof(struct map), 0);
	if (map == NULL) {
		rte_exit(1, "Could not allocate map");
	}

	map->addrs = rte_calloc("map addrs", capacity, sizeof(struct rte_ether_addr), 0);
	if (map->addrs == NULL) {
		rte_exit(1, "Could not allocate map addrs");
	}

	struct rte_table_hash_params rte_params = {
		.name = "rte map",
		.key_size = sizeof(uint64_t), // minimum size is uint64_t; must also be a power of 2; so we use the mask...
		.key_offset = 0,
		.key_mask = (uint8_t*) &key_mask,
		.n_keys = capacity,
		.n_buckets = rte_align32pow2(capacity / 4), // seems like a common thing to do given examples online
		.f_hash = rte_table_hash_crc_key48,
		.seed = 0
	};
	map->rte_map = rte_table_hash_ext_ops.f_create(&rte_params, rte_socket_id(), sizeof(struct map_value));
	if (map->rte_map == NULL) {
		rte_exit(1, "Could not create rte map");
	}

	return map;
}

static inline bool map_get(struct map* map, struct rte_ether_addr* addr, size_t* out_index, uint16_t* out_device)
{
	void* entries[64]; // required by DPDK to be exactly 64 elements
	struct rte_mbuf** pkts = (struct rte_mbuf**) &addr; // the table is meant for mbufs...
	uint64_t pkts_mask = 1; // only the first is set -> first bit
	uint64_t lookup_hit_mask = 0;
	int result = rte_table_hash_ext_ops.f_lookup(map->rte_map, pkts, pkts_mask, &lookup_hit_mask, entries);
	if (result != 0 || lookup_hit_mask == 0) {
		return false;
	}

	struct map_value* value = entries[0];
	*out_index = value->index;
	*out_device = value->device;
	return true;
}

static inline void map_set(struct map* map, struct rte_ether_addr* addr, size_t index, uint16_t device)
{
	rte_memcpy(&(map->addrs[index]), addr, sizeof(struct rte_ether_addr));
	struct map_value value = {
		.index = index,
		.device = device
	};
	int key_found = 0; // we don't care, but it needs to be passed in
	void* entry_ptr; // don't care either
	int result = rte_table_hash_ext_ops.f_add(map->rte_map, addr, &value, &key_found, &entry_ptr);
	if (result != 0) {
		rte_exit(1, "Could not set in map");
	}
}

static inline void map_remove(struct map* map, size_t index)
{
	int key_found = 0; // we don't care, but it needs to be passed in
	int result = rte_table_hash_ext_ops.f_delete(map->rte_map, &(map->addrs[index]), &key_found, NULL);
	if (result != 0) {
		rte_exit(1, "Could not set in map");
	}
}
