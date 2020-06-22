#include "os/skeleton/nf.h"

#include <string.h>

#include "os/config.h"
#include "os/clock.h"
#include "os/memory.h"
#include "os/structs/dchain.h"
#include "os/structs/map.h"


int64_t expiration_time;
os_net_ether_addr_t* addresses;
uint16_t* devices;
struct os_map* map;
struct os_dchain* allocator;

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

	addresses = os_memory_init(capacity, sizeof(os_net_ether_addr_t));
	devices = os_memory_init(capacity, sizeof(uint16_t));

	map = os_map_init(sizeof(os_net_ether_addr_t), capacity);
	if (map == 0) {
		return false;
	}

	allocator = os_dchain_init(capacity);
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
	if (os_map_get(map, &(ether_header->src_addr), &index)) {
		// TODO this is obviously wrong, need to check if they match
		os_dchain_refresh(allocator, time, index);
	} else {
		if (os_dchain_expire(allocator, time - expiration_time, &index)) {
			os_map_erase(map, &(addresses[index]));
		}
		if (os_dchain_add(allocator, time, &index)) {
			memcpy(addresses[index], ether_header->src_addr, sizeof(os_net_ether_addr_t));
			devices[index] = packet->device;
			os_map_put(map, &(addresses[index]), index);
		}
	} // It's OK if we can't get nor add, we can forward the packet anyway

	int64_t dst_time;
	if(os_map_get(map, &(ether_header->dst_addr), &index) && os_dchain_get(allocator, index, &dst_time) && time - expiration_time <= dst_time) {
		if (devices[index] != packet->device) {
			os_net_transmit(packet, devices[index], 0, 0, 0);
		}
	} else {
		os_net_flood(packet);
	}
}
