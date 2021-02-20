#include "compat/skeleton/polycube.h"

#include "uapi/linux/bpf.h"


extern struct bpf_map_def fwdtable;


bool nf_init(device_t max_device)
{
	(void) max_device;

	bpf_map_init(&fwdtable, false);

	return true;
}
