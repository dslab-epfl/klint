# Compatibility layer
CFLAGS += -isystem ../../os/include/compat
CFLAGS += --include compat/polycube.h

# The code expects this defined
CFLAGS += -D__always_inline=inline

# The code does pointer arithmetic with void*
CFLAGS += -Wno-pointer-arith

# The code declares unused labels
CFLAGS += -Wno-unused-label
