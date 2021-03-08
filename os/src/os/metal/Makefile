# Get current dir, see https://stackoverflow.com/a/8080530
OS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Our sources
SRCS += $(shell echo $(OS_DIR)/*.c)

# Force the use of our own time_t by preventing the stdlib from defining it and forcefully including ours so it's available
CFLAGS += -D__time_t_defined
CFLAGS += --include os/clock.h

# No stdlib
CFLAGS += -nostdlib
