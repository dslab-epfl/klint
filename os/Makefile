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
CFLAGS += -Wno-address-of-packed-member -Wno-padded

# Our includes
CFLAGS += -I$(SELF_DIR)/include

# Our sources
SRCS += $(shell echo $(SELF_DIR)/src/core/*.c)
SRCS += $(shell echo $(SELF_DIR)/src/user/*.c)

# Config
CFLAGS += '-D OS_CONFIG_FILENAME="$(abspath $(CONFIG_FILENAME))"'

# Build with the libnf
LDFLAGS += $(SELF_DIR)/../nf/$(NF)/libnf.so

build:
	$(CC) $(SRCS) $(CFLAGS) -o os.so
