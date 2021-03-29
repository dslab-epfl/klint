ifneq ($(NET),dpdk)
$(error The DPDK OS layer is only available when using DPDK for networking)
endif

# Get current dir, see https://stackoverflow.com/a/8080530
OS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Our sources
OS_SRCS += $(shell echo $(OS_DIR)/*.c)
