# Compatibility layer
CFLAGS += -isystem ../../os/include/compat
CFLAGS += -I ../../os/include/compat/uapi
CFLAGS += -I ../../os/include/compat/uapi/linux
CFLAGS += -I ../../os/include/compat/bpf

# Linux defines
CFLAGS += -D__u8=uint8_t
CFLAGS += -D__u16=uint16_t
CFLAGS += -D__u32=uint32_t
CFLAGS += -D__u64=uint64_t
CFLAGS += -D__be32=uint32_t

# Ignore #pragma unroll
CFLAGS += -Wno-unknown-pragmas

# Ignore dubious comparisons
CFLAGS += -Wno-sign-compare

# Allow void* in pointer arithmetic
CFLAGS += -Wno-pointer-arith

# Allow unused functions (because their use is #if-gated)
CFLAGS += -Wno-unused-function

# Allow unused variables (they seem to just be unused and could be removed...)
CFLAGS += -Wno-unused-variable

# Allow unused parameters (here too they are just unused and could be removed...)
CFLAGS += -Wno-unused-parameter

# For some reason gcc claims it might not be able to inline an unused function
CFLAGS += -Wno-attributes

# Give up on pedantism, there are a few empty struct values
CFLAGS += -Wno-pedantic

# Give up on padding
CFLAGS += -Wno-padded

# Katran triggers a bunch of 'comparison of distinct pointer types lacks a cast', which have no specific -W... switch in GCC but have one in Clang
ifeq (, $(findstring clang,$(CC)))
CFLAGS += -Wno-error
else
CFLAGS += -Wno-compare-distinct-pointer-types
endif

ifneq (, $(findstring clang,$(CC)))
# Katran uses a variable uninitialized, which Clang warns against
CFLAGS += -Wno-sometimes-uninitialized

# Allow reserved identifiers (i.e., beginning with __) as macros, which Clang warns against
CFLAGS += -Wno-reserved-id-macro

# Clang warns about BPF maps and functions not being static for some reason
CFLAGS += -Wno-missing-variable-declarations -Wno-missing-prototypes

# Allow implicit int conversions
CFLAGS += -Wno-implicit-int-conversion

# Allow implicit sign conversions (ouch)
CFLAGS += -Wno-sign-conversion

# Allow empty statements
CFLAGS += -Wno-extra-semi-stmt
endif
