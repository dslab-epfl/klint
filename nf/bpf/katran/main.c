#include <stdbool.h>

#define XDP_MAIN_FUNC balancer_ingress
#define XDP_SKELETON_RESTRICT
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
extern struct bpf_map_def server_id_map;
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

bool nf_init(device_t devices_count)
{
	(void) devices_count;

	bpf_map_havocinit(&vip_map);
	bpf_map_init(&lru_mapping); // The only map that must be empty, so that Katran will use fallback_cache instead (we don't support maps-of-maps yet)
	bpf_map_havocinit(&fallback_cache);
	bpf_map_havocinit(&ch_rings);
	bpf_map_havocinit(&reals);
	bpf_map_havocinit(&reals_stats);
	bpf_map_havocinit(&stats);
	bpf_map_havocinit(&server_id_map);
	bpf_map_havocinit(&ctl_array);

#ifdef LPM_SRC_LOOKUP
	bpf_map_havocinit(&lpm_src_v4);
	bpf_map_havocinit(&lpm_src_v6);
#endif

#ifdef KATRAN_INTROSPECTION
	bpf_map_havocinit(&event_pipe);
#endif

#ifdef INLINE_DECAP_GENERIC
	bpf_map_havocinit(&decap_dst);
	bpf_map_havocinit(&subprograms);
#endif

#ifdef GUE_ENCAP
	bpf_map_havocinit(&pckt_srcs);
#endif

	return true;
}
