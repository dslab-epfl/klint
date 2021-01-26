#include "net/skeleton.h"

#include "os/config.h"
#include "os/clock.h"
#include "os/memory.h"
#include "structs/pool.h"
#include "structs/map.h"


struct policer_bucket {
	uint64_t size;
	int64_t time;
};


uint16_t wan_device;
uint64_t rate;
uint64_t burst;
uint64_t max_flows;
struct policer_bucket* buckets;
uint32_t* addresses;
struct os_map* map;
struct os_pool* pool;

bool nf_init(uint16_t devices_count)
{
	if (devices_count != 2) {
		return false;
	}

	wan_device = os_config_get_u16("wan device");
	if (wan_device >= devices_count) {
		return false;
	}

	rate = os_config_get_u64("rate");
	if (rate == 0) {
		return false;
	}

	burst = os_config_get_u64("burst");
	if (burst == 0) {
		return false;
	}

	max_flows = os_config_get_u64("max flows");
	if (max_flows == 0 || max_flows > SIZE_MAX / 16 - 2) {
		return false;
	}

	buckets = os_memory_alloc(max_flows, sizeof(struct policer_bucket));
	addresses = os_memory_alloc(max_flows, sizeof(uint32_t));
	map = os_map_alloc(sizeof(uint32_t), max_flows);
	pool = os_pool_alloc(max_flows);

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
		int64_t time = os_clock_time();
		uint64_t index;
		if (os_map_get(map, &(ipv4_header->dst_addr), (void*) &index)) {
			os_pool_refresh(pool, time, index);
			uint64_t time_diff = time - buckets[index].time;
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

			if (os_pool_expire(pool, time, &index)) {
				os_map_remove(map, &(addresses[index]));
			}

			if (os_pool_borrow(pool, time, &index)) {
				addresses[index] = ipv4_header->dst_addr;
				os_map_set(map, &(addresses[index]), (void*) index);
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
