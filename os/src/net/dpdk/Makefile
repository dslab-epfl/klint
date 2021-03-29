# TODO make DPDK if not made

# This makefile takes over everything because DPDK
NO_DEFAULT_TARGETS := 1

# Get current dir, see https://stackoverflow.com/a/8080530
NET_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Usual DPDK vars
RTE_SDK := $(NET_DIR)/dpdk
RTE_TARGET ?= x86_64-native-linuxapp-gcc

# Force the use of our own time_t by preventing the stdlib from defining it and forcefully including ours so it's available
CFLAGS += -D__time_t_defined
CFLAGS += --include os/clock.h

# Silence warnings triggered by DPDK
CFLAGS += -Wno-address-of-packed-member -Wno-padded

# Batch size
CFLAGS += -DBATCH_SIZE=$(BATCH_SIZE)

# DPDK only accepts flags in EXTRA_*
EXTRA_CFLAGS := $(CFLAGS)
EXTRA_LDFLAGS := $(LDFLAGS)

# Custom task that does the DPDK stuff then moves the output to the expected location
default: all
	@if [ -d ./build ]; then cp ./build/app/$(OUTPUT) ./$(OUTPUT); rm -r ./build; fi

# DPDK, part 1
include $(RTE_SDK)/mk/rte.vars.mk

# Use existing sources, plus our main
SRCS-y += $(SRCS)
SRCS-y += $(NET_DIR)/main.c

# Keep the same binary name
APP := $(OUTPUT)

# DPDK, part 2
include $(RTE_SDK)/mk/rte.extapp.mk

# We don't track dependencies, oopsie
all: clean
