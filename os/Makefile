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
CFLAGS += -Wno-address-of-packed-member -Wno-padded -Wno-unused-function -Wno-deprecated-declarations -Wno-shadow -Wno-pedantic

# Our includes
CFLAGS += -I$(SELF_DIR)/include

# Our sources
SRCS += $(shell echo $(SELF_DIR)/src/core/*.c)
SRCS += $(shell echo $(SELF_DIR)/src/user/*.c)

# DPDK shim includes, along with files that DPDK sometimes assumes are included
CFLAGS += -isystem $(SELF_DIR)/src/dpdk-shim
CFLAGS += --include rte_os.h

# DPDK includes
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_eal/include
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_eal/include/generic
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_ethdev
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_kvargs
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_mbuf
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_mempool
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_net
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_ring
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/lib/librte_telemetry
CFLAGS += -isystem $(SELF_DIR)/src/dpdk/config

# DPDK sources
SRCS += $(shell echo $(SELF_DIR)/src/dpdk-shim/*.c)
SRCS += $(SELF_DIR)/src/dpdk/lib/librte_ethdev/rte_ethdev.c
SRCS += $(SELF_DIR)/src/dpdk/lib/librte_mbuf/rte_mbuf.c
SRCS += $(SELF_DIR)/src/dpdk/lib/librte_mempool/rte_mempool.c
SRCS += $(SELF_DIR)/src/dpdk/lib/librte_mempool/rte_mempool_ops.c

# Config
CFLAGS += '-D OS_CONFIG_FILENAME="$(abspath $(CONFIG_FILENAME))"'

# Build with the libnf
CFLAGS += $(NF)/libnf.so

build:
	$(CC) $(SRCS) $(CFLAGS) -o os.so
