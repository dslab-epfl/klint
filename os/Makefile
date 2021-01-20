ifndef NF
$(error Please define NF)
endif
ifndef CONFIG_FILENAME
$(error Please define CONFIG_FILENAME)
endif

# Get current dir, see https://stackoverflow.com/a/8080530
OS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Use our global makefile, for the compiler and such
include $(OS_DIR)/../Makefile.base

# TODO make this work properly, we shouldn't be getting warnings about undefined references in functions we don't use
CFLAGS += -ffunction-sections -fdata-sections -Wl,--gc-sections

# Our includes
CFLAGS += -I$(OS_DIR)/include

# Our sources
SRCS += $(shell echo $(OS_DIR)/src/os/*.c)

# Network layer
include $(OS_DIR)/src/net/Makefile

# Config
CFLAGS += '-D OS_CONFIG_FILENAME="$(abspath $(CONFIG_FILENAME))"'

# Build with the libnf
CFLAGS += $(NF)/libnf.so

build:
	$(CC) $(SRCS) $(CFLAGS) -o bin
