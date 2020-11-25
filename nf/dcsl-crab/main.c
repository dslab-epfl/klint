#define XDP_MAIN_FUNC xdp_prog_simple
#include "compat/skeleton/xdp.h"

#include "os/memory.h"

extern struct bpf_map_def targets_map;
extern struct bpf_map_def macs_map;
extern struct bpf_map_def targets_count;
extern struct bpf_map_def cpu_rr_idx;

bool nf_init(uint16_t devices_count)
{
	(void) devices_count;

	bpf_map_init(&targets_map, true);
	bpf_map_init(&macs_map, true);
	bpf_map_init(&targets_count, true);
	bpf_map_init(&cpu_rr_idx, true);

	return true;
}
