#include "os/skeleton/nf.h"

#include "os/config.h"
#include "os/clock.h"
#include "os/memory.h"
#include "os/structs/pool.h"
#include "os/structs/map.h"


struct policer_bucket {
	int64_t size;
	int64_t time;
};


uint16_t wan_device;
int64_t rate; // bytes/sec
int64_t burst; // bytes
uint64_t max_flows;
uint32_t* addresses;
struct policer_bucket* buckets;
struct os_map* map;
struct os_pool* chain;

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
	if (rate <= 0) {
		return false;
	}

	burst = os_config_get_u64("burst");
	if (burst <= 0) {
		return false;
	}

	max_flows = os_config_get_u64("max flows");
	if (max_flows == 0 || max_flows > SIZE_MAX / 16 - 2) {
		return false;
	}

	addresses = os_memory_alloc(max_flows, sizeof(uint32_t));
	buckets = os_memory_alloc(max_flows, sizeof(struct policer_bucket));
	map = os_map_alloc(sizeof(uint32_t), max_flows);
	chain = os_pool_alloc(max_flows);
	if (map == 0 || chain == 0) {
		return false;
	}

	return true;
}

void nf_handle(struct os_net_packet* packet)
{
	struct os_net_ether_header* ether_header;
	struct os_net_ipv4_header* ipv4_header;

	if (!os_net_get_ether_header(packet, &ether_header) || !os_net_get_ipv4_header(ether_header, &ipv4_header)) {
		return;
	}

	if (packet->device == wan_device) {
		int64_t time = os_clock_time();
		uint64_t index;
		if (os_map_get(map, &(ipv4_header->dst_addr), (void*) &index)) {
			os_pool_refresh(chain, time, index);
			int64_t time_diff = time - buckets[index].time;
			if (time_diff < burst * 1000000000l / rate) {
				buckets[index].size += time_diff * rate / 1000000000l;
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

			if (os_pool_expire(chain, time, &index)) {
				os_map_remove(map, &(addresses[index]));
			}

			if (os_pool_borrow(chain, time, &index)) {
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

	os_net_transmit(packet, 1 - packet->device, 0, 0, 0);
}
