NO_DEFAULT_TARGETS := true

# TODO strip symbols
compile:
	@xargo build --release
	@cp target/release/librust_policer.so $(LIB).so
