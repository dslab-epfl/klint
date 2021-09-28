`make` must be given the following env vars:

- `NF` is the path to the libNF
  - If it's shared object file (`.so`), `make` will produce a `bin` executable that dynamically links against that NF
  - If it's an object file (`.o`), `make` will produce a `bin` executable that is statically linked, with no runtime dependencies except for the chosen libOS's dependencies such as the Linux kernel

- `OS` is the libOS name
  - `linux` depends on the Linux kernel
  - `metal` depends on nothing and expects to run in kernel mode
  - `dpdk` depends on DPDK (does not support static linking)
  - Add your own! Just create a `Makefile` within that folder that adds to the `OS_SRCS` variable a list of absolute paths of source files

- `NET` is the network driver name
  - `tinynf` is an adaptation of the TinyNF driver (OSDI'20) for Intel 82599
  - `dpdk` is, well, DPDK
  - `dpdk-inline` doesn't work, do not use (the goal was to use the DPDK driver but without DPDK itself)
  - Add your own! Just create a `Makefile` within that folder that adds to the `NET_SRCS` variable a list of absolute paths of source files

- `NF_CONFIG_FILENAME` and `OS_CONFIG_FILENAME` are self-explanatory, the NF one is NF-dependent, for the OS one it's just a list of PCI devices, e.g.

```
{ .bus = 0x83, .device = 0x00, .function = 0x0 },
{ .bus = 0x85, .device = 0x00, .function = 0x0 },
```
