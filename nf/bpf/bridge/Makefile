# Compatibility layer
CFLAGS += -isystem ../../../os/include/compat

# For the 'bcc' folder
CFLAGS += -isystem .

# The code expects this defined
CFLAGS += -D__always_inline=inline

# Standard BPF issues
CFLAGS += -Wno-missing-variable-declarations -Wno-missing-prototypes

# Implicit integer truncation
CFLAGS += -Wno-implicit-int-conversion -Wno-shorten-64-to-32

# Pointer arithmetic with void*
CFLAGS += -Wno-pointer-arith

# The code declares unused labels
CFLAGS += -Wno-unused-label
