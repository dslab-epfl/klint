`make` must be given the following env vars:

- `NF` is the path to the libNF
  - If it's shared object file (`.so`), `make` will produce a `bin` executable that dynamically links against that NF
  - If it's an object file (`.o`), `make` will produce a `bin` executable that is statically linked, with no runtime dependencies except for the chosen libOS's dependencies such as the Linux kernel

- `OS` is the libOS name
  - `linux` depends on the Linux kernel
  - `metal` depends on nothing and expects to run in kernel mode
  - `dpdk` depends on DPDK (does not support static linking)
  - Add your own! Just create a `Makefile` within that folder that sets the `OS_SRCS` variable to a list of absolute paths of source files

- `NET` is the network driver name
  - `tinynf` is an adaptation of the TinyNF driver (OSDI'20) for Intel 82599
  - `dpdk` is, well, DPDK
  - Add your own! Just create a `Makefile` within that folder that sets the `NET_SRCS` variable to a list of absolute paths of source files

`make` can optionally be given `CC` and `CFLAGS` to override the compiler or add flags respectively.
