// Required by DPDK rte_config.h
// Includes architecture-specific stuff

// x86-64
// TODO make this hardware-independent somehow? or define this deep into a low-level layer of the OS, not here
#define RTE_CACHE_LINE_SIZE 64

// Whatever?
#define RTE_MAX_ETHPORTS 64

// Single core support
#define RTE_MAX_LCORE 1

// Avoid hardware-dependent stuff
#define RTE_FORCE_INTRINSICS 1

// Required (why is this even an option?)
#define RTE_USE_FUNCTION_VERSIONING 1

// Required when building DPDK files
#define ALLOW_INTERNAL_API 1
