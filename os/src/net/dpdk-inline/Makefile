# Get current dir, see https://stackoverflow.com/a/8080530
NET_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Batch size
CFLAGS += -DBATCH_SIZE=$(BATCH_SIZE)

# Silence warnings triggered by DPDK
CFLAGS += -Wno-address-of-packed-member -Wno-padded -Wno-unused-function -Wno-deprecated-declarations -Wno-shadow -Wno-pedantic -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-int-conversion -Wno-format-truncation

# Do not fail on missing functions, so we don't have to write pointless stubs for functions that are never executed
CFLAGS += -Wl,--unresolved-symbols=ignore-all

# Reuse the main file from standard DPDK
SRCS += $(NET_DIR)/../dpdk/main.c

# Our shims
SRCS += $(shell echo $(NET_DIR)/*.c)

# Our includes
CFLAGS += -isystem $(NET_DIR)/

# Reuse the DPDK submodule
DPDK_DIR := $(NET_DIR)/../dpdk/dpdk

# DPDK includes
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_eal/include
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_eal/include/generic
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_ethdev
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_kvargs
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_hash
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_mbuf
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_mempool
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_meter
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_net
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_pci
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_ring
CFLAGS += -isystem $(DPDK_DIR)/lib/librte_telemetry
CFLAGS += -isystem $(DPDK_DIR)/config
CFLAGS += -isystem $(DPDK_DIR)/drivers/bus/pci

# Intel 10G Ethernet driver sources, and necessary includes
CFLAGS += --include smmintrin.h
CFLAGS += -D rxrearm_nb=crc_len -D rxrearm_start=crc_len -D RTE_IXGBE_RXQ_REARM_THRESH=32 -D RTE_IXGBE_MAX_RX_BURST=32 # Horrible hack: use vec_sse without setting ARCH_X86 so DPDK itself remains neutral
SRCS += $(shell echo $(DPDK_DIR)/drivers/net/ixgbe/ixgbe_{ethdev,pf,rxtx,rxtx_vec_sse}.c)
SRCS += $(shell echo $(DPDK_DIR)/drivers/net/ixgbe/base/ixgbe_{api,common,phy,82599}.c)

# Allow our own stubs to include the driver stuff
CFLAGS += -I $(DPDK_DIR)/drivers/net/ixgbe

# Files that DPDK sometimes assumes are included
CFLAGS += --include rte_debug.h
CFLAGS += --include rte_config.h
CFLAGS += --include rte_os.h
# These ones are because the generic versions of these headers do not declare some functions declared by the arch-specific ones
CFLAGS += --include rte_atomic_header.h
CFLAGS += --include rte_byteorder_header.h
