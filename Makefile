# Get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

OS ?= linux
NET ?= tinynf
OS_CONFIG ?= $(SELF_DIR)/env/config

# we don't actually want dependency tracking
.PHONY: dummy
dummy:

## tool

TOOL_DIR := $(SELF_DIR)/tool
TOOL_VENV_DIR := $(TOOL_DIR)/venv

.PHONY: tool
tool: | tool-venv

.PHONY: tool-venv
tool-venv: $(TOOL_VENV_DIR)/.env-done

TOOL_MODS := $(dir $(wildcard $(TOOL_DIR)/*/__init__.py))
TOOL_SRCS := $(shell find $(TOOL_MODS) -type f -name '*.py')

$(TOOL_VENV_DIR)/.venv-created:
	python3 -m venv $(TOOL_VENV_DIR)
	touch $@
$(TOOL_VENV_DIR)/.env-done: $(TOOL_SRCS) | $(TOOL_VENV_DIR)/.venv-created
	. $(TOOL_VENV_DIR)/bin/activate && \
		pip install $(TOOL_DIR)
	touch $@

.PHONY: tool-test
tool-test: | tool-venv
	. $(TOOL_VENV_DIR)/bin/activate && \
		python -m unittest discover --start-directory $(TOOL_DIR)

TOOL_DIST_DIR := $(TOOL_DIR)/dist

.PHONY: tool-build
tool-build: $(TOOL_SRCS) | tool-venv
	. $(TOOL_VENV_DIR)/bin/activate && \
		pip install build && \
		python -m build $(TOOL_DIR)

.PHONY: tool-constraints
tool-constraints: $(TOOL_SRCS) | tool-venv
	. $(TOOL_VENV_DIR)/bin/activate && \
		pip freeze --exclude klint > $(TOOL_DIR)/constraints

## others

compile-%: dummy
	$(MAKE) -C $(SELF_DIR)/nf/$* -f $(SELF_DIR)/nf/Makefile.nf

build-%: compile-%
	@if [ ! -f $(OS_CONFIG) ]; then echo 'Please write an OS config file in $(OS_CONFIG), see $(SELF_DIR)/env/ReadMe.md'; exit 1; fi
	$(MAKE) -C $(SELF_DIR)/env NF=$(SELF_DIR)/nf/$*/libnf.so OS=$(OS) NET=$(NET) OS_CONFIG=$(OS_CONFIG) NF_CONFIG=$(SELF_DIR)/nf/$*/config

verify-%: compile-% | tool-venv
	. $(TOOL_VENV_DIR)/bin/activate && \
		klint libnf $(SELF_DIR)/nf/$*/libnf.so $(SELF_DIR)/nf/$*/spec.py

benchmark-%: compile-%
	@if [ ! -f $(SELF_DIR)/benchmarking/config ]; then echo 'Please set the benchmarking config, see $(SELF_DIR)/benchmarking/ReadMe.md'; exit 1; fi
	@if [ '$(NF_LAYER)' = '' ]; then echo 'Please set NF_LAYER to the layer of your NF, e.g., 2 for a bridge, 4 for a TCP/UDP firewall'; exit 1; fi
	NF=$(SELF_DIR)/nf/$* OS=$(OS) NET=$(NET) $(SELF_DIR)/benchmarking/bench.sh '$(SELF_DIR)/env' standard $(NF_LAYER)

compile-all: dummy
	@for d in $(SELF_DIR)/nf/* ; do if [ -d $$d ]; then $(MAKE) -C $(SELF_DIR) compile-$$(basename $$d); fi ; done
