# Compatibility layer
CFLAGS += -isystem ../../os/include/compat
CFLAGS += --include compat/polycube.h

# The code expects u* aliases
CFLAGS += -Du8=uint8_t -Du16=uint16_t -Du32=uint32_t -Du64=uint64_t

# The code does pointer arithmetic with void*
CFLAGS += -Wno-pointer-arith

# The code declares unused labels
CFLAGS += -Wno-unused-label
