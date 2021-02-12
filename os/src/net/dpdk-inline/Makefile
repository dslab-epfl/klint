# Get current dir, see https://stackoverflow.com/a/8080530
NET_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Batch size
CFLAGS += -DBATCH_SIZE=$(BATCH_SIZE)

# Silence warnings triggered by DPDK
CFLAGS += -Wno-address-of-packed-member -Wno-padded -Wno-unused-function -Wno-deprecated-declarations -Wno-shadow -Wno-pedantic -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-int-conversion -Wno-format-truncation

# Do not fail on missing functions, so we don't have to write pointless stubs for functions that are never executed
CFLAGS += -Wl,--unresolved-symbols=ignore-all

# Reuse the one for standard DPDK; no extra sources needed
SRCS += $(NET_DIR)/../dpdk/main.c

# DPDK shim includes, along with files that DPDK sometimes assumes are included
CFLAGS += -isystem $(NET_DIR)/dpdk-shim
CFLAGS += --include rte_debug.h
CFLAGS += --include rte_config.h
CFLAGS += --include rte_os.h
# These ones are because the generic versions of these headers do not declare some functions declared by the arch-specific ones
CFLAGS += --include rte_atomic_header.h
CFLAGS += --include rte_byteorder_header.h

# DPDK includes
CFLAGS += -isystem $(NET_DIR)/dpdk/lib/librte_eal/include
CFLAGS += -isystem $(NET_DIR)/dpdk/lib/librte_eal/include/generic
CFLAGS += -isystem $(NET_DIR)/dpdk/lib/librte_ethdev
CFLAGS += -isystem $(NET_DIR)/dpdk/lib/librte_kvargs
CFLAGS += -isystem $(NET_DIR)/dpdk/lib/librte_hash
CFLAGS += -isystem $(NET_DIR)/dpdk/lib/librte_mbuf
CFLAGS += -isystem $(NET_DIR)/dpdk/lib/librte_meter
CFLAGS += -isystem $(NET_DIR)/dpdk/lib/librte_net
CFLAGS += -isystem $(NET_DIR)/dpdk/lib/librte_pci
CFLAGS += -isystem $(NET_DIR)/dpdk/lib/librte_ring
CFLAGS += -isystem $(NET_DIR)/dpdk/lib/librte_telemetry
CFLAGS += -isystem $(NET_DIR)/dpdk/config
CFLAGS += -isystem $(NET_DIR)/dpdk/drivers/bus/pci

# DPDK shim sources
SRCS += $(shell echo $(NET_DIR)/dpdk-shim/*.c)

# DPDK sources
SRCS += $(NET_DIR)/dpdk/lib/librte_ethdev/rte_ethdev.c
SRCS += $(NET_DIR)/dpdk/lib/librte_mbuf/rte_mbuf.c
SRCS += $(NET_DIR)/dpdk/drivers/bus/pci/pci_common.c

# Intel 10G Ethernet driver sources, and necessary includes
CFLAGS += --include smmintrin.h
CFLAGS += -D rxrearm_nb=crc_len -D rxrearm_start=crc_len -D RTE_IXGBE_RXQ_REARM_THRESH=32 -D RTE_IXGBE_MAX_RX_BURST=32 # Horrible hack: use vec_sse without setting ARCH_X86 so DPDK itself remains neutral
SRCS += $(shell echo $(NET_DIR)/dpdk/drivers/net/ixgbe/ixgbe_{ethdev,pf,rxtx,rxtx_vec_sse}.c)
SRCS += $(shell echo $(NET_DIR)/dpdk/drivers/net/ixgbe/base/ixgbe_{api,common,phy,82599}.c)
