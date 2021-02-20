NO_DEFAULT_TARGET := true

compile:
	@xargo build --release
	@cp target/release/librs_vigor_policer.so $(LIB)
	@$(STRIP) $(STRIPFLAGS) $(LIB)
