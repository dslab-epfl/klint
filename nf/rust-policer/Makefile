NO_DEFAULT_TARGETS := true

$(HOME)/.cargo/bin/xargo:
	cargo install xargo

# TODO strip symbols
compile: $(HOME)/.cargo/bin/xargo
	@$< build --release
	@cp target/release/librust_policer.so $(LIB).so
