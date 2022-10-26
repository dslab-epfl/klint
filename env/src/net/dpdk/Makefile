ifndef NF_DYNAMIC
$(error Sorry, DPDK net only supports dynamic linking for now)
endif

# This makefile takes over everything because DPDK
NO_DEFAULT_TARGETS := 1

# Get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Usual DPDK vars
RTE_SDK := $(SELF_DIR)/dpdk
RTE_TARGET := x86_64-native-linuxapp-gcc

# Force the use of our own time_t by preventing the stdlib from defining it and forcefully including ours so it's available
CFLAGS += -D__time_t_defined
CFLAGS += --include os/clock.h

# Silence warnings triggered by DPDK
CFLAGS += -Wno-address-of-packed-member -Wno-padded

# Batch size
BATCH_SIZE ?= 1
CFLAGS += -DBATCH_SIZE=$(BATCH_SIZE)

# DPDK only accepts flags in EXTRA_*
EXTRA_CFLAGS := $(CFLAGS)

# Forward definition of DPDK's goal
.PHONY: all
.DEFAULT_GOAL := all

$(RTE_SDK)/.installed:
	git submodule update --checkout --init --force $(RTE_SDK)
	# fix build with gcc 11
	curl https://patches.dpdk.org/series/12380/mbox/ | patch -d $(RTE_SDK) -p1
	$(MAKE) -C $(RTE_SDK) install T=$(RTE_TARGET) DESTDIR=. MAKE_PAUSE=n EXTRA_CFLAGS=-Wno-error
	touch $@
$(RTE_SDK)/mk/rte.vars.mk $(RTE_SDK)/mk/rte.extapp.mk: $(RTE_SDK)/.installed
	touch --reference $< $@

# DPDK, part 1
include $(RTE_SDK)/mk/rte.vars.mk

# Use existing sources, plus our main
SRCS-y += $(SRCS) $(STRUCTS_SRCS) $(VERIF_SRCS) $(OS_SRCS) $(NF_DYNAMIC)
SRCS-y += $(SELF_DIR)/main.c

# Keep the same binary name
APP := $(OUTPUT)

# DPDK, part 2
include $(RTE_SDK)/mk/rte.extapp.mk
