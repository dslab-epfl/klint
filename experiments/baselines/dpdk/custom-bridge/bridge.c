#include "bridge.h"

#include "map.h"
#include "lru.h"


static time_t expiration_time;
static struct map* map;
static struct lru* lru;


bool nf_init(uint16_t devices_count, time_t expiration_time, size_t capacity)
{
	if (devices_count < 2) {
		return false;
	}

	if (expiration_time < 0) {
		return false;
	}

	map = map_alloc(capacity);
	lru = lru_alloc(capacity);

	return true;
}

// TODO same issue as vigor-bridge re: checking map_get's device
void nf_handle(uint8_t* packet, uint16_t packet_length, uint16_t device, uint64_t time)
{
	struct rte_ether_hdr* ether_header = (struct rte_ether_hdr*) packet;

	uint16_t out_device;
	size_t index;

	if (map_get(map, &(ether_header->src_addr), &index, &out_device)) {
		lru_touch(lru, time, index);
	} else {
		if (lru_expire(allocator, time - expiration_time, &index)) {
			map_remove(map, index);
		}
		if (lru_get_unused(lru, time, &index)) {
			map_set(map, &(ether_header->src_addr), index, devicex);
		}
	}

	if(map_get(map, &(ether_header->dst_addr), &index, &out_device)) {
		if (out_device != packet->device) {
			// TODO TX on out_device
		}
	} else {
		// TODO flood
	}
}
