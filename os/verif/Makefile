ifndef RTE_SDK
$(error Please define RTE_SDK)
endif
ifndef RTE_TARGET
$(error Please define RTE_TARGET)
endif

# Get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# allow the use of advanced globs in paths
SHELL := /bin/bash -O extglob -O globstar -c

# Number of devices
NF_DEVICES ?= 2


# and now for the actual verification stuff... this is adapted from Vigor


# Cleanup
CLEAN_COMMAND := rm -rf *.bc *.os *.ll
# Compilation
COMPILE_COMMAND := clang
# Linking with klee-uclibc, but without some methods we are modeling (not sure why they're in klee-uclibc.bca);
# also purge the pointless GNU linker things so KLEE doesn't warn about module asm
LINK_COMMAND := llvm-ar x $(KLEE_BUILD_PATH)/Release+Debug+Asserts/lib/klee-uclibc.bca && \
                rm -f sleep.os vfprintf.os socket.os exit.os fflush_unlocked.os fflush.os && \
                llvm-link -o nf_raw.bc  *.os *.bc && \
                llvm-dis -o nf_raw.ll nf_raw.bc && \
                sed -i -e 's/module asm ".section .gnu.warning.*"//g' \
                       -e 's/module asm "\\09.previous"//g' \
                       -e 's/module asm ""//g' \
                       nf_raw.ll && \
                llvm-as -o nf_raw.bc nf_raw.ll
# Optimization; analyze and remove as much provably dead code as possible
# (exceptions are models; also, mem* functions, not sure why it DCEs them since they are used... maybe related to LLVM having intrinsics for them?)
OPT_EXCEPTIONS := memset,memcpy,memmove,stub_abort,stub_free,stub_hardware_read,stub_hardware_write,stub_prefetch,stub_rdtsc,stub_socket,stub_strerror,stub_delay
OPT_COMMAND := opt -basicaa -basiccg -internalize \
                   -internalize-public-api-list=main,$(OPT_EXCEPTIONS) \
                   -globaldce nf_raw.bc \
                   > nf.bc
# KLEE verification;
# if something takes longer than expected, try --max-solver-time=3 --debug-report-symbdex (to avoid symbolic indices)
 #-solver-backend=z3 \ TODO this can be removed?
VERIF_COMMAND := /usr/bin/time -v \
                 klee -no-externals -allocate-determ \
                      -allocate-determ-start-address=0x00040000000 -allocate-determ-size=1000 \
                      -dump-call-traces -dump-call-trace-prefixes \
                      -exit-on-error -max-memory=750000 -search=dfs \
                      -condone-undeclared-havocs \
                 nf.bc

# Basic flags: only compile, emit debug code, in LLVM format,
#              with checks for overflows (but not unsigned overflows -
#              they're not UB and DPDK depends on them)
#              also no unused-value, DPDK triggers that...
VERIF_FLAGS := -c -g -emit-llvm -fsanitize=signed-integer-overflow -Wno-unused-value
# Basic includes: NF root, KLEE, DPDK cmdline
VERIF_INCLUDES := -I $(SELF_DIR) -I $(KLEE_INCLUDE) -I $(RTE_SDK)/lib/librte_cmdline
# Basic defines
VERIF_DEFS := -D_GNU_SOURCE -DKLEE_VERIFICATION
# Number of devices
VERIF_DEFS += -DSTUB_DEVICES_COUNT=$(NF_DEVICES)
# Fake NF base
VERIF_FILES := $(SELF_DIR)/fake-nf.c
# Models
VERIF_FILES += $(SELF_DIR)/models/**/*.c
# DPDK cmdline parsing library, always included,
# we don't want/need to model it... and the string function it uses
VERIF_FILES += $(RTE_SDK)/lib/librte_cmdline/*.c \
               $(RTE_SDK)/lib/librte_eal/common/eal_common_string_fns.c
# CPUFLAGS is set to a sentinel value; usually it's passed from the DPDK build system
VERIF_WITHDPDK_DEFS := -DRTE_COMPILE_TIME_CPUFLAGS=424242
# We need librte_eal/common because eal_private.h is in there, required by eal_thread.c...
# We need bus/pci because the linuxapp PCI stuff requires a private.h file in there...
# net/ixgbe is for model hardware (the ixgbe driver)
VERIF_WITHDPDK_INCLUDES := -I $(RTE_SDK)/$(RTE_TARGET)/include \
			   -I $(RTE_SDK)/lib/librte_eal/common \
			   -I $(RTE_SDK)/drivers/bus/pci \
			   -I $(RTE_SDK)/drivers/net/ixgbe
# And then some special DPDK includes: builtin models for built-ins DPDK uses,
# rte_config.h because many files forget to include it
VERIF_WITHDPDK_INCLUDES += --include=models/builtin.h \
                           --include=rte_config.h
# Platform-independent and Linux-specific EAL
DPDK_FILES += $(RTE_SDK)/lib/librte_eal/common/*.c \
              $(RTE_SDK)/lib/librte_eal/linuxapp/eal/*.c
# Default ring mempool driver
DPDK_FILES += $(RTE_SDK)/drivers/mempool/ring/rte_mempool_ring.c
# Other libraries, except acl and distributor which use CPU intrinsics (there is a generic version of distributor, but we don't need it)
# and power has been broken for a while: http://dpdk.org/ml/archives/dev/2016-February/033152.html
DPDK_FILES += $(RTE_SDK)/lib/!(librte_acl|librte_distributor|librte_power)/*.c
# PCI driver support (for ixgbe driver)
DPDK_FILES += $(RTE_SDK)/drivers/bus/pci/*.c $(RTE_SDK)/drivers/bus/pci/linux/*.c
# ixgbe driver
IXGBE_FILES := $(RTE_SDK)/drivers/net/ixgbe/ixgbe_{fdir,flow,ethdev,ipsec,pf,rxtx,tm}.c \
               $(RTE_SDK)/drivers/net/ixgbe/base/ixgbe_{api,common,phy,82599}.c
# combine everything
VERIF_FILES += $(DPDK_FILES) $(IXGBE_FILES)



# Our additions...
VERIF_FLAGS += -I$(SELF_DIR)/../include
VERIF_FLAGS += -I$(SELF_DIR)/../../config/include
VERIF_FILES += $(shell echo $(SELF_DIR)/../src/**/*.c)
NF_ARGS := --no-shconf

# Clean every time just in case
symbex: clean
	@$(COMPILE_COMMAND) $(VERIF_DEFS) $(VERIF_WITHDPDK_DEFS) $(VERIF_INCLUDES) \
	                    $(VERIF_WITHDPDK_INCLUDES) $(VERIF_FILES) \
	                    $(VERIF_WITHDPDK_FILES) $(VERIF_FLAGS)
	@$(LINK_COMMAND)
	@$(OPT_COMMAND)
	@$(VERIF_COMMAND) $(NF_ARGS)
	@$(CLEAN_BUILD_ARTIFACTS_COMMAND)

clean:
	@$(CLEAN_COMMAND)
