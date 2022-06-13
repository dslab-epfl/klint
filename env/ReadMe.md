## Code organization

- `docker` contains a Dockerfile to deploy a full binary to a Docker container, as a proof-of-concept for deployment
- `include` contains the definitions of abstractions:
  - `arch` contains architecture-specific abstractions such as endianness conversion
  - `net` contains network abstractions such as packet headers
  - `os` contains OS abstractions such as memory allocation
  - `proof` contains proof annotations used in the proofs for the data structures and memory allocator
  - `structs` contains data structure operations
  - `verif` contains abstractions drivers must use to be full-stack verifiable
- `src` contains the implementations of the abstractions:
  - `net` contains two network drivers, `dpdk` and `tinynf`
  - `os` contains three "operating systems", `dpdk` (which uses DPDK on any OS), `linux`, and `metal` (i.e., bare metal) as well as shared code between the three
  - `structs` contains the implementations of all data structures
  - `verif` contains the implementations of the abstractions used by drivers for full-stack verification
- `Makefile` is the makefile to build a full binary given an NF binary and a choice of OS+driver
- `Makefile.benchmarking` is the Makefile with build & run tasks to benchmark the network functions
- `verify.sh` is a script to verify the parts of the implementation that are manually verified: the data structures and the memory allocator


## Building

`make` requires multiple environment variables including an already-built NF binary; a full usage example is: `make NF=../nf/nop/libnf.so OS=linux NET=tinynf OS_CONFIG=./config NF_CONFIG=../nf/nop/config`

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

- `NF_CONFIG` and `OS_CONFIG` are self-explanatory, the NF one is NF-dependent, for the OS one it's just a list of PCI devices, e.g.,
```
{ .bus = 0x83, .device = 0x00, .function = 0x0 },
{ .bus = 0x85, .device = 0x00, .function = 0x0 },
```

## Building the documentation
In order to get the documentation for the klint environment C code library perform the following steps
1. Go to this [website](https://www.doxygen.nl/manual/install.html) and install doxygen
2. Run doxygen Doxyfile in `env`
3. Open the `index.html` file in the `html` folder created