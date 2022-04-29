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
