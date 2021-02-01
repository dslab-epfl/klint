ifneq ($(NET),dpdk)
$(error The DPDK OS layer is only available when using DPDK for networking)
endif

# Get current dir, see https://stackoverflow.com/a/8080530
OS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Our sources
SRCS += $(shell echo $(OS_DIR)/*.c)

# Allow "internal" APIs, for the page size
CFLAGS += -DALLOW_INTERNAL_API
