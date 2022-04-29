# Get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

NF_DIRS := $(filter-out bpf, $(shell find . -mindepth 1 -maxdepth 1 -type d -print | cut -c3-))

.PHONY: default
default: $(NF_DIRS)

.PHONY: $(NF_DIRS)
$(NF_DIRS):
	@$(MAKE) -C $@ -f $(SELF_DIR)/Makefile.nf

verify-%: %
	@$(SELF_DIR)/../tool/klint.py libnf $(SELF_DIR)/$*/libnf.so $(SELF_DIR)/$*/spec.py

.PHONY: phony_dummy
phony_dummy:

clean_all: $(patsubst %, clean-%, $(filter-out rust-policer, $(NF_DIRS)))

clean-%: phony_dummy
	@$(MAKE) -C $(SELF_DIR)/$* -f $(SELF_DIR)/Makefile.nf clean
