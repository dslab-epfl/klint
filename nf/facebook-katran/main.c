#include <stdbool.h>

#define XDP_MAIN_FUNC balancer_ingress
#include "compat/skeleton/xdp.h"

#include "balancer_consts.h"

#include "bpf.h"

extern struct bpf_map_def vip_map;
extern struct bpf_map_def lru_mapping;
extern struct bpf_map_def fallback_cache;
extern struct bpf_map_def ch_rings;
extern struct bpf_map_def reals;
extern struct bpf_map_def reals_stats;
extern struct bpf_map_def stats;
extern struct bpf_map_def quic_mapping;
extern struct bpf_map_def ctl_array;

#ifdef LPM_SRC_LOOKUP
extern struct bpf_map_def lpm_src_v4;
extern struct bpf_map_def lpm_src_v6;
#endif

#ifdef KATRAN_INTROSPECTION
extern struct bpf_map_def lpm_src_v4;
#endif

#ifdef INLINE_DECAP_GENERIC
extern struct bpf_map_def lpm_src_v4;
extern struct bpf_map_def lpm_src_v4;
#endif

#ifdef GUE_ENCAP
extern struct bpf_map_def lpm_src_v4;
#endif

bool nf_init(uint16_t devices_count)
{
	(void) devices_count;

	bpf_map_init(&vip_map, true);
	bpf_map_init(&lru_mapping, false); // is a map of maps; will lead to using fallback_cache as default
	bpf_map_init(&fallback_cache, false); // managed by the BPF part
	bpf_map_init(&ch_rings, true);
	bpf_map_init(&reals, true);
	bpf_map_init(&reals_stats, true);
	bpf_map_init(&stats, true);
	bpf_map_init(&quic_mapping, true);
	bpf_map_init(&ctl_array, true);

#ifdef LPM_SRC_LOOKUP
	bpf_map_init(&lpm_src_v4, true);
	bpf_map_init(&lpm_src_v6, true);
#endif

#ifdef KATRAN_INTROSPECTION
	bpf_map_init(&event_pipe, true);
#endif

#ifdef INLINE_DECAP_GENERIC
	bpf_map_init(&decap_dst, true);
	bpf_map_init(&subprograms, true);
#endif

#ifdef GUE_ENCAP
	bpf_map_init(&pckt_srcs, true);
#endif

	return true;
}
