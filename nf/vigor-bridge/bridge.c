#include "net/skeleton.h"

#include "os/config.h"
#include "os/clock.h"
#include "os/memory.h"
#include "structs/pool.h"
#include "structs/map.h"


uint64_t expiration_time;
net_ether_addr_t* addresses;
uint16_t* devices;
struct os_map* map;
struct os_pool* allocator;

bool nf_init(uint16_t devices_count)
{
	if (devices_count < 2) {
		return false;
	}

	expiration_time = os_config_get_u64("expiration time");

	uint64_t capacity = os_config_get_u64("capacity"); // TODO should be size_t (and in other NFs!)
	if (capacity == 0 || capacity > 2*65536) {
		return false;
	}

	addresses = os_memory_alloc(capacity, sizeof(net_ether_addr_t));
	devices = os_memory_alloc(capacity, sizeof(uint16_t));

	map = os_map_alloc(sizeof(net_ether_addr_t), capacity);
	allocator = os_pool_alloc(capacity);

	return true;
}

void nf_handle(struct net_packet* packet)
{
	struct net_ether_header* ether_header;
	if (!net_get_ether_header(packet, &ether_header)) {
		return;
	}

	uint64_t time = os_clock_time_ns();

	size_t index;
	if (os_map_get(map, &(ether_header->src_addr), &index)) {
		// TODO this is obviously wrong, need to check if they match
		os_pool_refresh(allocator, time, index);
	} else {
		if (os_pool_expire(allocator, time - expiration_time, &index)) {
			os_map_remove(map, &(addresses[index]));
		}
		if (os_pool_borrow(allocator, time, &index)) {
			os_memory_copy(ether_header->src_addr, addresses[index], sizeof(ether_header->src_addr));
			devices[index] = packet->device;
			os_map_set(map, &(addresses[index]), index);
		}
	} // It's OK if we can't get nor add, we can forward the packet anyway

	if(os_map_get(map, &(ether_header->dst_addr), &index)) {
		if (devices[index] != packet->device) {
			net_transmit(packet, devices[index], 0);
		}
	} else {
		net_flood(packet);
	}
}
