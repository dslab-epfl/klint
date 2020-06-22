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

# TODO: this should have dependency tracking, proper targets, and stuff
compile:
	@$(CC) $(SRCS) $(CFLAGS) -shared -o lib$(LIB).so
	@$(STRIP) $(STRIPFLAGS) lib$(LIB).so
