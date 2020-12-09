ifndef NF
$(error Please define the NF variable)
endif
ifndef RTE_TARGET
$(error Please define RTE_TARGET)
endif
ifndef RTE_SDK
$(error Please define RTE_SDK)
endif

# Get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# DPDK, part 1
include $(RTE_SDK)/mk/rte.vars.mk

# Use our global makefile, for the compiler and such
include $(SELF_DIR)/../Makefile.base

# Silence warnings triggered by DPDK
CFLAGS += -Wno-address-of-packed-member -Wno-padded

# Our includes
CFLAGS += -I$(SELF_DIR)/include

# Our source
SRCS-y += $(shell echo $(SELF_DIR)/src/**/*.c)

# Config includes
CFLAGS += -I$(SELF_DIR)/../config/include

# Build with the libnf
LDFLAGS += $(SELF_DIR)/../nf/$(NF)/libnf.so

# Build with the libconfig
LDFLAGS += $(SELF_DIR)/../config/libconfig.so

# Name of the binary
APP := nf

# DPDK, part 2
include $(RTE_SDK)/mk/rte.extapp.mk

# make sure nothing weird happens with dependencies
all: clean
