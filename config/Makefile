ifndef CONFIG_FILENAME
$(error Please define CONFIG_FILENAME)
endif

# Get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Base makefile
include $(SELF_DIR)/../Makefile.base

# Our headers
CFLAGS += -I $(SELF_DIR)/include

# Our source
SRCS += $(shell echo $(SELF_DIR)/src/*.c)

# Magic sauce: the config file as a definition
CFLAGS += '-D CONFIG_FILENAME="$(abspath $(CONFIG_FILENAME))"'

# Name of the lib
LIB := config

compile:
	@$(CC) $(SRCS) $(CFLAGS) -shared -o lib$(LIB).so
	@$(STRIP) $(STRIPFLAGS) lib$(LIB).so
