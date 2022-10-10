NO_DEFAULT_TARGETS := true

SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

TARGET := $(shell cargo -Vv | awk '/^host:/ {print $$2}')

$(LIB).so: $(SELF_DIR)/target/$(TARGET)/release/librust_policer.so
	cp $^ $@

$(SELF_DIR)/target/$(TARGET)/release/librust_policer.so:
	cargo build --release \
		-Z build-std=std,panic_abort \
		-Z build-std-features=panic_immediate_abort \
		--target $(TARGET)
