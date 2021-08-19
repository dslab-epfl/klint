# Compatibility layer; also, the code expects common one level up and addresses it as ../, let's trick it
CFLAGS += -I ../../os/include/compat/uapi
CFLAGS += -I ../../os/include/compat
CFLAGS += -I common

# The code expects this defined
CFLAGS += -D__always_inline=inline

# Arithmetic with void*
CFLAGS += -Wno-pointer-arith

# Implicit sign changes
CFLAGS += -Wno-sign-conversion
CFLAGS += -Wno-sign-compare

# Wrong alignment stuff (probably correct given the actual alignment of packets...)
CFLAGS += -Wno-cast-align
CFLAGS += -Wno-address-of-packed-member

# #pragma unroll
CFLAGS += -Wno-unknown-pragmas

# Unused code
CFLAGS += -Wno-unused-macros

ifeq (, $(findstring clang,$(CC)))
# The code triggers a bunch of 'comparison of distinct pointer types lacks a cast', which have no specific -W... switch in GCC...
CFLAGS += -Wno-error
else
# ... but they do have ine in clang!
CFLAGS += -Wno-compare-distinct-pointer-types
# Implicit truncation of ints
CFLAGS += -Wno-implicit-int-conversion -Wno-shorten-64-to-32
# The #ifdef used for header includes begin with __
CFLAGS += -Wno-reserved-id-macro
# Standard BPF issues
CFLAGS += -Wno-missing-variable-declarations -Wno-missing-prototypes
endif
