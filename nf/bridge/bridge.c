#include "net/skeleton.h"

#include "os/config.h"
#include "os/memory.h"
#include "os/time.h"
#include "structs/index_pool.h"
#include "structs/map.h"

#include "spanning_tree.h"


static struct stp_state* stp_state;
static uint64_t* addresses;
static device_t* devices;
static struct map* map;
static struct index_pool* allocator;


bool nf_init(device_t devices_count)
{
	if (devices_count < 2) {
		return false;
	}

	uint64_t self_bid;
	time_t expiration_time;
	size_t capacity;
	if (!os_config_get_u64("bid", &self_bid) || !os_config_get_time("expiration time", &expiration_time) || !os_config_get_size("capacity", &capacity)) {
		return false;
	}

	stp_state = stp_init(devices_count, self_bid);
	addresses = os_memory_alloc(capacity, sizeof(uint64_t));
	devices = os_memory_alloc(capacity, sizeof(device_t));
	map = map_alloc(sizeof(uint64_t), capacity);
	allocator = index_pool_alloc(capacity, expiration_time);
	return true;
}

static inline uint64_t addr_to_int(struct net_ether_addr* addr)
{
	return ((uint64_t) addr->bytes[0]) | ((uint64_t) addr->bytes[1] << 8) | ((uint64_t) addr->bytes[2] << 16) | ((uint64_t) addr->bytes[3] << 24) | ((uint64_t) addr->bytes[4] << 32) | ((uint64_t) addr->bytes[5] << 40);
}

void nf_handle(struct net_packet* packet)
{
/*	if (stp_handle(stp_state, packet)) {
		return;
	}
*/
	struct net_ether_header* ether_header;
	if (!net_get_ether_header(packet, &ether_header)) {
		return;
	}

	uint64_t src = addr_to_int(&(ether_header->src_addr));
	uint64_t dst = addr_to_int(&(ether_header->dst_addr));

	size_t index;
	bool was_used;
	if (map_get(map, &src, &index)) {
		index_pool_refresh(allocator, packet->time, index);
		devices[index] = packet->device; // in case the device changed
	} else if (index_pool_borrow(allocator, packet->time, &index, &was_used)) {
		if (was_used) {
			map_remove(map, &(addresses[index]));
		}

		addresses[index] = src;
		map_set(map, &(addresses[index]), index);

		devices[index] = packet->device;
	} // It's OK if we can't get nor add, we can forward the packet anyway

	if (map_get(map, &dst, &index)) {
		if (devices[index] != packet->device) {
			net_transmit(packet, devices[index], 0);
		}
	} else {
		net_flood_except(packet, stp_blocked_devices(stp_state), 0);
	}
}
