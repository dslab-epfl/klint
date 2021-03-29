# Get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Base makefile
include $(SELF_DIR)/Makefile.base

# No libC, thus no extra stuff like __cxa_finalize
CFLAGS += -nostdlib

# Allow only freestanding headers, nothing else (hacky but no other way to do it apparently... https://stackoverflow.com/q/2681304)
CFLAGS += -ffreestanding -nostdinc -isystem $(shell gcc -print-search-dirs | head -n 1 | cut -d ':' -f 2)/include

# OS headers
CFLAGS += -I$(SELF_DIR)/os/include

# NF source
SRCS += $(shell echo *.c)

# Name of the library
LIB := libnf

# NF-specific makefile if necessary
ifneq (,$(wildcard Makefile))
include Makefile
endif

ifndef NO_DEFAULT_TARGETS
default: $(LIB).so $(LIB).o


$(LIB).so: $(SRCS)
	@$(CC) $(CFLAGS) -shared -o $@ $^
	@$(STRIP) $(STRIPFLAGS) $@


$(LIB).o: $(subst .c,.o,$(SRCS))
	@$(LD) -r $^ -o $@

%.o: %.c
	@$(CC) $(CFLAGS) -c -o $@ $<


clean:
	@rm -f **/*.o *.so
endif
