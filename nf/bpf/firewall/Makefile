# Compatibility layer
CFLAGS += -isystem ../../os/include/compat
CFLAGS += -isystem ../../os/include/compat/uapi

# Somehow the code expects the Linux UDP header to be included
CFLAGS += --include linux/udp.h

# Standard BPF issues
CFLAGS += -Wno-missing-variable-declarations -Wno-missing-prototypes

# Pointer arithmetic on void*
CFLAGS += -Wno-pointer-arith

# Implicit integer truncation
CFLAGS += -Wno-implicit-int-conversion -Wno-shorten-64-to-32

# Implicit sign conversion
CFLAGS += -Wno-sign-conversion

# Unused code
CFLAGS += -Wno-unused-label -Wno-unused-variable -Wno-unused-macros

# Macros without providing any args for the variadic parameter, illegal in ISO C (or with clang)
CFLAGS += -std=gnu17
CFLAGS += -Wno-gnu-zero-variadic-macro-arguments

# Structs need padding
CFLAGS += -Wno-padded
