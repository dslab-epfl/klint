#pragma once

#include <stddef.h>
#include <time.h>

#include <rte_common.h>
#include <rte_malloc.h>


struct lru_entry {
	// For both free and occupied:
	struct lru_entry* next;

	// Only for occupied:
	struct lru_entry* prev;
	time_t time;
};

struct lru {
	struct lru_entry* entries;
	struct lru_entry* free;
	struct lru_entry* occupied;
};


static inline struct lru* lru_alloc(size_t capacity)
{
	struct lru* lru = rte_zmalloc("lru", sizeof(struct lru), 0);
	if (lru == NULL) {
		rte_exit(1, "Could not allocate LRU");
	}

	lru->entries = rte_calloc("lru entries", capacity, sizeof(struct lru_entry), 0);
	if (lru->entries == NULL) {
		rte_exit(1, "Could not allocate LRU entries");
	}

	lru->free = rte_malloc("lru free", sizeof(struct lru_entry), 0);
	if (lru->free == NULL) {
		rte_exit(1, "Could not allocate LRU free");
	}

	lru->occupied = rte_malloc("lru occupied", sizeof(struct lru_entry), 0);
	if (lru->occupied == NULL) {
		rte_exit(1, "Could not allocate LRU occupied");
	}

	// Full free list
	lru->free->next = &(lru->entries[0]);
	for (size_t n = 0; n < capacity - 1; n++) {
		lru->entries[n].next = &(lru->entries[n + 1]);
	}
	lru->entries[capacity - 1].next = lru->free;

	// Empty occupied list
	lru->occupied->prev = lru->occupied;
	lru->occupied->next = lru->occupied;

	return lru;
}

static inline bool lru_get_unused(struct lru* lru, time_t time, size_t* out_index)
{
	if (lru->free->next == lru->free) {
		return false;
	}

	struct lru_entry* entry = lru->free->next;

	// Unlink from free
	lru->free->next = entry->next;

	// Link into occupied
	entry->prev = lru->occupied;
	entry->next = lru->occupied->next;
	lru->occupied->next->prev = entry;
	lru->occupied->next = entry;

	// Update
	entry->time = time;

	*out_index = (size_t) (entry - lru->entries);
	return true;
}

static inline void lru_touch(struct lru* lru, time_t time, size_t index)
{
	struct lru_entry* entry = &(lru->entries[index]);

	// Unlink from occupied
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;

	// Link into occupied
	entry->prev = lru->occupied;
	entry->next = lru->occupied->next;
	lru->occupied->next->prev = entry;
	lru->occupied->next = entry;

	// Update
	entry->time = time;
}

static inline bool lru_expire(struct lru* lru, time_t cutoff_time, size_t* out_index)
{
	struct lru_entry* entry = lru->occupied->prev;
	if (entry == lru->occupied) {
		return false;
	}

	if (entry->time >= cutoff_time) {
		return false;
	}

	// Unlink from occupied
	entry->prev->next = entry;
	entry->next->prev = entry;

	// Link into free
	entry->next = lru->free->next;
	lru->free->next = entry;

	*out_index = (size_t) (entry - lru->entries);
	return true;
}
