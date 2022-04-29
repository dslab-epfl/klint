# Get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

OS ?= linux
NET ?= tinynf
OS_CONFIG ?= $(SELF_DIR)/env/config

# we don't actually want dependency tracking
.PHONY: dummy
dummy:

compile-%: dummy
	@$(MAKE) -C $(SELF_DIR)/nf/$* -f $(SELF_DIR)/nf/Makefile.nf >/dev/null

build-%: compile-%
	@if [ ! -f $(OS_CONFIG) ]; then echo 'Please write an OS config file in $(OS_CONFIG), see $(SELF_DIR)/env/ReadMe.md'; exit 1; fi
	@$(MAKE) -C $(SELF_DIR)/env NF=$(SELF_DIR)/nf/$*/libnf.so OS=$(OS) NET=$(NET) OS_CONFIG=$(OS_CONFIG) NF_CONFIG=$(SELF_DIR)/nf/$*/config >/dev/null

verify-%: compile-%
	@if ! which python >/dev/null; then echo 'No python found, perhaps you need to set up the virtualenv?'; exit 1; fi
	@$(SELF_DIR)/tool/klint.py libnf $(SELF_DIR)/nf/$*/libnf.so $(SELF_DIR)/nf/$*/spec.py

benchmark-%: compile-%
	@if [ ! -f $(SELF_DIR)/benchmarking/config ]; then echo 'Please set the benchmarking config, see $(SELF_DIR)/benchmarking/ReadMe.md'; exit 1; fi
	@if [ '$(NF_LAYER)' = '' ]; then echo 'Please set NF_LAYER to the layer of your NF, e.g., 2 for a bridge, 4 for a TCP/UDP firewall'; exit 1; fi
	@NF=$(SELF_DIR)/nf/bridge OS=$(OS) NET=$(NET) $(SELF_DIR)/benchmarking/bench.sh '$(SELF_DIR)/env' standard $(NF_LAYER)

compile-all: dummy
	@for d in $(SELF_DIR)/nf/* ; do if [ -d $$d ] && [ "$$(basename $$d)" != 'bpf' ]; then $(MAKE) -C $(SELF_DIR) compile-$$(basename $$d) >/dev/null ; fi ; done
	@for d in $(SELF_DIR)/nf/bpf/*; do cd $$d && ./compile-bpf.sh ; done
