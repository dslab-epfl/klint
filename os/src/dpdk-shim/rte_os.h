#pragma once

// This header contains a polyfill for our stub OS, i.e., stuff not otherwise defined but that DPDK expects of all OSes

#include <stdint.h>


// We don't support multicore for now so this can be anything
typedef uint64_t rte_cpuset_t;
