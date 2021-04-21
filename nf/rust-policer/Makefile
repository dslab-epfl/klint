NO_DEFAULT_TARGETS := true

# TODO strip symbols
compile:
	@xargo build --release
	@cp target/release/librs_vigor_policer.so $(LIB).so
