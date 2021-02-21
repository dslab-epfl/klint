#include "net/skeleton.h"

#include "os/config.h"
#include "os/clock.h"
#include "os/memory.h"
#include "structs/map.h"
#include "structs/pool.h"


struct net_ether_addr* addresses;
device_t* devices;
struct os_map* map;
struct os_pool* allocator;


bool nf_init(device_t devices_count)
{
	if (devices_count < 2) {
		return false;
	}

	time_t expiration_time = os_config_get_time("expiration time");
	size_t capacity = os_config_get_size("capacity");

	addresses = os_memory_alloc(capacity, sizeof(struct net_ether_addr));
	devices = os_memory_alloc(capacity, sizeof(device_t));

	map = os_map_alloc(sizeof(struct net_ether_addr), capacity);
	allocator = os_pool_alloc(capacity, expiration_time);

	return true;
}

void nf_handle(struct net_packet* packet)
{
	struct net_ether_header* ether_header;
	if (!net_get_ether_header(packet, &ether_header)) {
		return;
	}

	time_t time = os_clock_time_ns();

	size_t index;
	if (os_map_get(map, &(ether_header->src_addr), &index)) {
		// TODO this is obviously wrong, need to check if they match
		os_pool_refresh(allocator, time, index);
	} else {
		bool was_used;
		if (os_pool_borrow(allocator, time, &index, &was_used)) {
			if (was_used) {
				os_map_remove(map, &(addresses[index]));
			}

			ether_header->src_addr = addresses[index];
			devices[index] = packet->device;
			os_map_set(map, &(addresses[index]), index);
		}
	} // It's OK if we can't get nor add, we can forward the packet anyway

	if (os_map_get(map, &(ether_header->dst_addr), &index)) {
		if (devices[index] != packet->device) {
			net_transmit(packet, devices[index], 0);
		}
	} else {
		net_flood(packet);
	}
}
