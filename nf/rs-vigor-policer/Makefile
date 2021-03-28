NO_DEFAULT_TARGETS := true

compile:
	@xargo build --release
	@cp target/release/librs_vigor_policer.so $(LIB).so
	@$(STRIP) $(STRIPFLAGS) $(LIB).so
