ifndef NF
$(error Please define NF)
endif
ifndef OS
$(error Please define OS)
endif
ifndef NET
$(error Please define NET)
endif
ifndef NF_CONFIG_FILENAME
$(error Please define NF_CONFIG_FILENAME)
endif
ifndef OS_CONFIG_FILENAME
$(error Please define OS_CONFIG_FILENAME)
endif

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

# Shared or static depending on what the libNF is (shared obj or obj)
ifneq (,$(findstring .so,$(NF)))
NF_DYNAMIC := $(NF)
else
NF_STATIC := $(NF)
CFLAGS += -static
endif

# Structs
STRUCTS_SRCS := $(shell echo $(THIS_DIR)/src/structs/*.c)

# Verif
VERIF_SRCS := $(shell echo $(THIS_DIR)/src/verif/*.c)

# OS (the makefile adds to OS_SRCS)
OS_SRCS := $(shell echo $(THIS_DIR)/src/os/*.c)
include $(THIS_DIR)/src/os/$(OS)/Makefile

# Network (the makefile defines NET_SRCS)
include $(THIS_DIR)/src/net/$(NET)/Makefile

# All sources that must be split so that their functions are separated and can be modelled during verification
SPLIT_SRCS := $(STRUCTS_SRCS) $(VERIF_SRCS) $(OS_SRCS)
SPLIT_OBJ := split.obj
NF_OBJ := nf.obj

ifdef NF_FULL_LTO
# For experiments only, unverifiable
NO_LTO_FLAG :=
else
# The overall compile must not use LTO, so that we can be sure all symbols declared in SPLIT_OBJ are still there (e.g. not inlined) and thus can be modeled
NO_LTO_FLAG := -fno-lto
endif

ifndef NO_DEFAULT_TARGETS
default: clean $(OUTPUT)

$(OUTPUT): $(NF_OBJ) $(SPLIT_OBJ) $(NF_DYNAMIC)
	@$(CC) $(CFLAGS) $(NO_LTO_FLAG) -o $@ $^

# Strip the NF object, to mimic realistic conditions in which the NF is compiled along with networking code by a developer and given to an operator, without any symbols
$(NF_OBJ): $(subst .c,.o,$(NET_SRCS)) $(NF_STATIC)
	@$(LD) -s -r $^ -o $@

$(SPLIT_OBJ): $(subst .c,.o,$(SPLIT_SRCS))
	@$(LD) -r $^ -o $@

%.o: %.c
	@$(CC) $(CFLAGS) -c -o $@ $<


.PHONY: clean
clean:
	@rm -f **/*.o $(NF_OBJ) $(SPLIT_OBJ) $(OUTPUT)
endif
