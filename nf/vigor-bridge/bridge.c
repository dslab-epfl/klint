#include "net/skeleton.h"

#include "os/config.h"
#include "os/clock.h"
#include "os/memory.h"
#include "structs/index_pool.h"
#include "structs/map.h"

#include "spanning_tree.h"


static struct stp_state* stp_state;
static struct net_ether_addr* addresses;
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
	addresses = os_memory_alloc(capacity, sizeof(struct net_ether_addr));
	devices = os_memory_alloc(capacity, sizeof(device_t));
	map = map_alloc(sizeof(struct net_ether_addr), capacity);
	allocator = index_pool_alloc(capacity, expiration_time);
	return true;
}

void nf_handle(struct net_packet* packet)
{
	if (stp_handle(stp_state, packet)) {
		return;
	}

	struct net_ether_header* ether_header;
	if (!net_get_ether_header(packet, &ether_header)) {
		return;
	}

	time_t time = os_clock_time_ns();

	size_t index;
	if (map_get(map, &(ether_header->src_addr), &index)) {
		// TODO this is obviously wrong, need to check if they match
		index_pool_refresh(allocator, time, index);
	} else {
		bool was_used;
		if (index_pool_borrow(allocator, time, &index, &was_used)) {
			if (was_used) {
				map_remove(map, &(addresses[index]));
			}

			addresses[index] = ether_header->src_addr;
			devices[index] = packet->device;
			map_set(map, &(addresses[index]), index);
		}
	} // It's OK if we can't get nor add, we can forward the packet anyway

	if (map_get(map, &(ether_header->dst_addr), &index)) {
		if (devices[index] != packet->device) {
			net_transmit(packet, devices[index], 0);
		}
	} else {
		net_flood_except(packet, stp_blocked_devices(stp_state), 0);
	}
}
