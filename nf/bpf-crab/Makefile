# Compatibility layer; also, the code expects common one level up and addresses it as ../, let's trick it
CFLAGS += -I ../../os/include/compat/uapi
CFLAGS += -I ../../os/include/compat
CFLAGS += -I common

# The code expects this defined
CFLAGS += -D__always_inline=inline

# Arithmetic with void*
CFLAGS += -Wno-pointer-arith

# Ignore #pragma unroll
CFLAGS += -Wno-unknown-pragmas

# Ignore weird address taking
CFLAGS += -Wno-address-of-packed-member

# Ignore weird comparisons
CFLAGS += -Wno-sign-compare

# The code triggers a bunch of 'comparison of distinct pointer types lacks a cast', which have no specific -W... switch in GCC but have one in Clang
ifeq (, $(findstring clang,$(CC)))
CFLAGS += -Wno-error
else
CFLAGS += -Wno-compare-distinct-pointer-types
endif
