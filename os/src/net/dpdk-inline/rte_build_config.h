// Required by DPDK rte_config.h
// Includes architecture-specific stuff

#include "arch/cache.h"


#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE

// Whatever?
#define RTE_MAX_ETHPORTS 64

// Single core support
#define RTE_MAX_LCORE 1

// Avoid hardware-dependent stuff
#define RTE_FORCE_INTRINSICS 1

// Required when building DPDK files
#define ALLOW_INTERNAL_API 1
