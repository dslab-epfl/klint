#include "net/skeleton.h"

#include "os/config.h"
#include "os/clock.h"
#include "os/memory.h"
#include "structs/map.h"
#include "structs/pool.h"


struct policer_bucket {
	uint64_t size;
	time_t time;
};


device_t wan_device;
uint64_t rate;
uint64_t burst;
struct policer_bucket* buckets;
uint32_t* addresses;
struct os_map* map;
struct os_pool* pool;

bool nf_init(device_t devices_count)
{
	if (devices_count != 2) {
		return false;
	}

	wan_device = os_config_get_device("wan device", devices_count);

	rate = os_config_get_u64("rate");
	if (rate == 0) {
		return false;
	}

	burst = os_config_get_u64("burst");
	if (burst == 0) {
		return false;
	}

	size_t max_flows = os_config_get_size("max flows");
	buckets = os_memory_alloc(max_flows, sizeof(struct policer_bucket));
	addresses = os_memory_alloc(max_flows, sizeof(uint32_t));
	map = os_map_alloc(sizeof(uint32_t), max_flows);
	pool = os_pool_alloc(max_flows, 1000000000ull * burst / rate);

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
		time_t time = os_clock_time_ns();
		size_t index;
		if (os_map_get(map, &(ipv4_header->dst_addr), &index)) {
			os_pool_refresh(pool, time, index);
			time_t time_diff = time - buckets[index].time;
			if (time_diff < burst / rate) {
				buckets[index].size += time_diff * rate;
				if (buckets[index].size > burst) {
					buckets[index].size = burst;
				}
			} else {
				buckets[index].size = burst;
			}
			buckets[index].time = time;

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
			if (os_pool_borrow(pool, time, &index, &was_used)) {
				if (was_used) {
					os_map_remove(map, &(addresses[index]));
				}

				addresses[index] = ipv4_header->dst_addr;
				os_map_set(map, &(addresses[index]), index);
				buckets[index].size = burst - packet->length;
				buckets[index].time = time;
			} else {
				// No more space
				return;
			}
		}
	} // no policing for outgoing packets

	net_transmit(packet, 1 - packet->device, 0);
}
