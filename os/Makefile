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

# Our includes
CFLAGS += -I$(THIS_DIR)/include

# Config
CFLAGS += '-D OS_CONFIG_DATA=$(shell cat $(OS_CONFIG_FILENAME))'
CFLAGS += '-D NF_CONFIG_DATA=$(shell cat $(NF_CONFIG_FILENAME))'

ifeq ($(OS),none)
# Include the libnf directly
SRCS += $(shell echo $(NF)/*.c)
# Shared lib
CFLAGS += -shared
else
# Build with the libnf
ifeq (,$(findstring -static,$(CFLAGS)))
LDFLAGS += $(NF)/libnf.so
else
LDFLAGS += $(NF)/libnf.a
endif

# OS
SRCS += $(shell echo $(THIS_DIR)/src/os/*.c)
include $(THIS_DIR)/src/os/$(OS)/Makefile

# Structs
SRCS += $(shell echo $(THIS_DIR)/src/structs/*.c)
endif

# Verif
SRCS += $(shell echo $(THIS_DIR)/src/verif/*.c)

# Network
include $(THIS_DIR)/src/net/$(NET)/Makefile

ifndef NO_DEFAULT_TARGET
build:
	@$(CC) $(SRCS) $(CFLAGS) $(LDFLAGS) -o $(OUTPUT)
	@$(STRIP) $(STRIPFLAGS) $(OUTPUT)
endif
