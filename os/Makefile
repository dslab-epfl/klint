ifndef NF
$(error Please define NF)
endif
ifndef NF_CONFIG_FILENAME
$(error Please define NF_CONFIG_FILENAME)
endif
ifndef OS_CONFIG_FILENAME
$(error Please define OS_CONFIG_FILENAME)
endif

OS ?= linux
NET ?= tinynf

OUTPUT := bin

# Get current dir, see https://stackoverflow.com/a/8080530
THIS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Use our global makefile, for the compiler and such
include $(THIS_DIR)/../Makefile.base

# TODO make this work properly, we shouldn't be getting warnings about undefined references in functions we don't use
CFLAGS += -ffunction-sections -fdata-sections -Wl,--gc-sections

# Our includes
CFLAGS += -I$(THIS_DIR)/include

# Config
CFLAGS += '-D OS_CONFIG_FILENAME="$(abspath $(OS_CONFIG_FILENAME))"'
CFLAGS += '-D NF_CONFIG_FILENAME="$(abspath $(NF_CONFIG_FILENAME))"'

# Build with the libnf
LDFLAGS += $(NF)/libnf.so

# OS
SRCS += $(shell echo $(THIS_DIR)/src/os/$(OS)/*.c)

# Structs
SRCS += $(shell echo $(THIS_DIR)/src/structs/*.c)

# Network
include $(THIS_DIR)/src/net/$(NET)/Makefile

ifndef NO_DEFAULT_TARGET
build:
	@$(CC) $(SRCS) $(CFLAGS) $(LDFLAGS) -o $(OUTPUT)
	@$(STRIP) $(STRIPFLAGS) $(OUTPUT)
endif
