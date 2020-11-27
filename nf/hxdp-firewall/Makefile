# Compatibility layer
CFLAGS += -isystem ../../os/include/compat
CFLAGS += -isystem ../../os/include/compat/uapi

# Somehow the code expects the Linux UDP header to be included
CFLAGS += --include linux/udp.h

# The code uses pointer arithmetic on void*
CFLAGS += -Wno-pointer-arith

# The code has some unused things
CFLAGS += -Wno-unused-label -Wno-unused-variable

# The code calls macros without providing any args for the variadic parameter, illegal in ISO C
CFLAGS += -std=gnu17
