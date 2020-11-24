#pragma once

#include <stdint.h>

// just ignore this for now... but use the arguments to avoid triggering "unused parameter" warnings
#define bpf_csum_diff(r1, from_size, r3, to_size, seed) 0 * r1 * from_size * (uintptr_t)r3 * to_size * seed
