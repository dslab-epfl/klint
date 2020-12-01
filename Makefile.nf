# Get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Base makefile
include $(SELF_DIR)/Makefile.base

# Disable stdlib, this is an NF, we only use the "OS" abstractions
CFLAGS += -nostdlib

# OS headers
CFLAGS += -I$(SELF_DIR)/os/include

# NF source
SRCS += $(shell echo *.c)

# Name of the app
LIB := nf

# NF-specific makefile if necessary
ifneq (,$(wildcard Makefile))
include Makefile
endif

# Disable standard includes then add them back, so that ours are preferred
CFLAGS += -nostdinc -isystem $(shell $(CC) --print-file-name=include) -isystem /usr/local/include -isystem /usr/include/x86_64-linux-gnu -isystem /usr/include

ifndef NO_DEFAULT_TARGET
# TODO: this should have dependency tracking, proper targets, and stuff
compile:
	@$(CC) $(SRCS) $(CFLAGS) -shared -o lib$(LIB).so
	@$(STRIP) $(STRIPFLAGS) lib$(LIB).so
endif
