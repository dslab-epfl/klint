#include "net/skeleton.h"
#include "os/config.h"
#include "os/memory.h"
#include "os/time.h"
#include "structs/index_pool.h"
#include "structs/map.h"

struct policer_bucket {
	uint64_t size;
	time_t time;
};

static device_t wan_device;
static uint64_t rate;
static uint64_t burst;
static struct policer_bucket* buckets;
static uint32_t* addresses;
static struct map* map;
static struct index_pool* pool;

bool nf_init(device_t devices_count)
{
	if (devices_count != 2) {
		return false;
	}

	size_t max_flows;
	if (!os_config_get_device("wan device", devices_count, &wan_device) || !os_config_get_u64("rate", &rate) || !os_config_get_u64("burst", &burst) ||
	    !os_config_get_size("max flows", &max_flows)) {
		return false;
	}

	if (rate == 0 || burst == 0) {
		return false;
	}

	buckets = os_memory_alloc(max_flows, sizeof(struct policer_bucket));
	addresses = os_memory_alloc(max_flows, sizeof(uint32_t));
	map = map_alloc(sizeof(uint32_t), max_flows);
	pool = index_pool_alloc(max_flows, 1000000000ull * burst / rate);
	return true;
}

void nf_handle(struct net_packet* packet)
{
	struct net_ether_header* ether_header;
	struct net_ipv4_header* ipv4_header;

	if (!net_get_ether_header(packet, &ether_header) || !net_get_ipv4_header(ether_header, &ipv4_header)) {
		return;
	}

	if (packet->device == wan_device) {
		size_t index;
		if (map_get(map, &(ipv4_header->dst_addr), &index)) {
			index_pool_refresh(pool, packet->time, index);
			time_t time_diff = packet->time - buckets[index].time;
			if (time_diff < burst / rate) {
				buckets[index].size += time_diff * rate;
				if (buckets[index].size > burst) {
					buckets[index].size = burst;
				}
			} else {
				buckets[index].size = burst;
			}
			buckets[index].time = packet->time;

			if (buckets[index].size > packet->length) {
				buckets[index].size -= packet->length;
			} else {
				// Packet too big
				return;
			}
		} else {
			if (packet->length > burst) {
				// Unknown flow, length greater than burst
				return;
			}

			bool was_used;
			if (index_pool_borrow(pool, packet->time, &index, &was_used)) {
				if (was_used) {
					map_remove(map, &(addresses[index]));
				}

				addresses[index] = ipv4_header->dst_addr;
				map_set(map, &(addresses[index]), index);
				buckets[index].size = burst - packet->length;
				buckets[index].time = packet->time;
			} else {
				// No more space
				return;
			}
		}
	} // no policing for outgoing packets

	net_transmit(packet, 1 - packet->device, 0);
}
