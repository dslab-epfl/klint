ifndef NF
$(error Please define NF)
endif
ifndef CONFIG_FILENAME
$(error Please define CONFIG_FILENAME)
endif

# Get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Use our global makefile, for the compiler and such
include $(SELF_DIR)/../Makefile.base

# Silence warnings triggered by DPDK
CFLAGS += -Wno-address-of-packed-member -Wno-padded -Wno-unused-function -Wno-deprecated-declarations -Wno-shadow -Wno-pedantic -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-int-conversion

# Do not fail on missing functions, so we don't have to write pointless stubs for functions that are never executed
CFLAGS += -Wl,--warn-unresolved-symbols

# Our includes
CFLAGS += -I$(SELF_DIR)/include

# Our sources
SRCS += $(shell echo $(SELF_DIR)/src/core/*.c)
SRCS += $(shell echo $(SELF_DIR)/src/user/*.c)

# DPDK shim includes, along with files that DPDK sometimes assumes are included
CFLAGS += -isystem $(SELF_DIR)/src/dpdk-shim
CFLAGS += --include rte_config.h
CFLAGS += --include rte_os.h
# These ones are because the generic versions of these headers do not declare some functions declared by the arch-specific ones
CFLAGS += --include rte_atomic_header.h
CFLAGS += --include rte_byteorder_header.h

# DPDK includes
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_eal/include
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_eal/include/generic
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_ethdev
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_kvargs
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_hash
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_mbuf
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_mempool
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_meter
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_net
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_pci
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_ring
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_telemetry
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/config
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/drivers/bus/pci

# DPDK sources
SRCS += $(shell echo $(SELF_DIR)/src/dpdk-shim/*.c)
SRCS += $(SELF_DIR)/src/dpdk/lib/librte_ethdev/rte_ethdev.c
SRCS += $(SELF_DIR)/src/dpdk/lib/librte_mbuf/rte_mbuf.c
SRCS += $(SELF_DIR)/src/dpdk/lib/librte_mempool/rte_mempool.c
SRCS += $(SELF_DIR)/src/dpdk/lib/librte_mempool/rte_mempool_ops.c
SRCS += $(SELF_DIR)/src/dpdk/lib/librte_mempool/rte_mempool_ops_default.c
SRCS += $(SELF_DIR)/src/dpdk/drivers/bus/pci/pci_common.c

# Intel 10G Ethernet driver sources, and necessary includes
CFLAGS += --include smmintrin.h
CFLAGS += -D rxrearm_nb=crc_len -D rxrearm_start=crc_len -D RTE_IXGBE_RXQ_REARM_THRESH=32 -D RTE_IXGBE_MAX_RX_BURST=32 # Horrible hack: use vec_sse without setting ARCH_X86 so DPDK itself remains neutral
SRCS += $(shell echo $(RTE_SDK)/drivers/net/ixgbe/ixgbe_{ethdev,pf,rxtx,rxtx_vec_sse}.c)
SRCS += $(shell echo $(RTE_SDK)/drivers/net/ixgbe/base/ixgbe_{api,common,phy,82599}.c)

# Config
CFLAGS += '-D OS_CONFIG_FILENAME="$(abspath $(CONFIG_FILENAME))"'

# Build with the libnf
CFLAGS += $(NF)/libnf.so

build:
	$(CC) $(SRCS) $(CFLAGS) -o os.so
