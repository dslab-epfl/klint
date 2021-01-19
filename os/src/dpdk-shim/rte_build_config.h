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

// Required because the ixgbe driver has a bug:
// it references ixgbe_rx_queue->rxrearm_nb even if it's not defined (and is conditionally defined on X86/ARM)
#define RTE_ARCH_X86 1
// and thus we must define this too
enum rte_cpu_flag_t { RTE_CPUFLAG_EM64T = 85 };
// might as well
#define RTE_ARCH_X86_64 1
