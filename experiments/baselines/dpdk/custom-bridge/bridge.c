#include "lru.h"
#include "map.h"
#include "nf.h"


static time_t expiration_time;
static struct map* map;
static struct lru* lru;


bool nf_init(uint16_t devices_count, time_t exp_time, size_t capacity)
{
	if (devices_count < 2) {
		return false;
	}

	if (exp_time < 0) {
		return false;
	}

	expiration_time = exp_time;
	map = map_alloc(capacity);
	lru = lru_alloc(capacity);

	return true;
}

// TODO same issue as vigor-bridge re: checking map_get's device
void nf_handle(struct rte_mbuf* mbuf, time_t time)
{
	struct rte_ether_hdr* ether_header = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);

	uint16_t out_device;
	size_t index;

	if (map_get(map, &(ether_header->s_addr), &index, &out_device)) {
		lru_touch(lru, time, index);
	} else {
		if (lru_expire(lru, time - expiration_time, &index)) {
			map_remove(map, index);
		}
		if (lru_get_unused(lru, time, &index)) {
			map_set(map, &(ether_header->s_addr), index, mbuf->port);
		}
	}

	if(map_get(map, &(ether_header->d_addr), &index, &out_device)) {
		if (out_device != mbuf->port) {
			tx_packet(mbuf, out_device);
		}
	} else {
		flood_packet(mbuf);
	}
}
