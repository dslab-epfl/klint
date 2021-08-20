#include <stdbool.h>

#define XDP_MAIN_FUNC xdp_prog_polycube
#include "compat/skeleton/xdp.h"

#include "uapi/linux/bpf.h"


extern struct bpf_map_def fwdtable;


bool nf_init(device_t devices_count)
{
	(void) devices_count;

	bpf_map_init(&fwdtable);

	return true;
}
