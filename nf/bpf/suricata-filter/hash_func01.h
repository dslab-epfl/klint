#pragma once


static __always_inline __u32 SuperFastHash (const char *data, int len, __u32 initval) {
	return bpf_get_prandom_u32();
}
