#include "os/skeleton/nf.h"

#include <string.h>

#include "os/config.h"
#include "os/clock.h"
#include "os/memory.h"
#include "os/structs/pool.h"
#include "os/structs/map.h"


int64_t expiration_time;
os_net_ether_addr_t* addresses;
uint16_t* devices;
struct os_map* map;
struct os_pool* allocator;

bool nf_init(uint16_t devices_count)
{
	if (devices_count < 2) {
		return false;
	}

	uint64_t capacity = os_config_get_u64("capacity");
	if (capacity == 0 || capacity > 2*65536) {
		return false;
	}

	expiration_time = (int64_t) os_config_get_u64("expiration time");
	if (expiration_time <= 0) {
		return false;
	}

	addresses = os_memory_alloc(capacity, sizeof(os_net_ether_addr_t));
	devices = os_memory_alloc(capacity, sizeof(uint16_t));

	map = os_map_alloc(sizeof(os_net_ether_addr_t), capacity);
	if (map == 0) {
		return false;
	}

	allocator = os_pool_alloc(capacity);
	if (allocator == 0) {
		return false;
	}

	return true;
}

void nf_handle(struct os_net_packet* packet)
{
	struct os_net_ether_header* ether_header;
	if (!os_net_get_ether_header(packet, &ether_header)) {
		return;
	}

	int64_t time = os_clock_time();

	uint64_t index;
	if (os_map_get(map, &(ether_header->src_addr), (void*) &index)) {
		// TODO this is obviously wrong, need to check if they match
		os_pool_refresh(allocator, time, index);
	} else {
		if (os_pool_expire(allocator, time - expiration_time, &index)) {
			os_map_remove(map, &(addresses[index]));
		}
		if (os_pool_borrow(allocator, time, &index)) {
			memcpy(addresses[index], ether_header->src_addr, sizeof(os_net_ether_addr_t));
			devices[index] = packet->device;
			os_map_set(map, &(addresses[index]), (void*) index);
		}
	} // It's OK if we can't get nor add, we can forward the packet anyway

	int64_t dst_time;
	if(os_map_get(map, &(ether_header->dst_addr), (void*) &index) && os_pool_used(allocator, index, &dst_time) && time - expiration_time <= dst_time) {
		if (devices[index] != packet->device) {
			os_net_transmit(packet, devices[index], 0, 0, 0);
		}
	} else {
		os_net_flood(packet);
	}
}
