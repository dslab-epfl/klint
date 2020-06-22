#include "os/skeleton/nf.h"

#include "klee/klee.h"


bool nf_init(uint16_t devices_count)
{
	klee_trace_ret();
	klee_trace_param_u16(devices_count, "devices_count");
	return klee_int("nf_init_result") != 0;
}

void nf_handle(struct os_net_packet* packet)
{
}
