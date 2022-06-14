This is the artifact for the paper "Automated Verification of Network Function Binaries" presented at NSDI'22.


## Repository structure

- `benchmarking` contains the scripts for benchmarks (building upon those from the TinyNF artifact) 
- `experiments` contains the scripts to reproduce the results in the paper
- `nf` contains the network functions we wrote or adapted
- `env` contains the environment abstractions for network functions and implementations of these abstractions
- `tool` contains the Klint tool
- `Makefile` contains some end-to-end targets, see below
- `Makefile.base` is the common Makefile for all C code
- `.clang-format` can be applied with `find . -regex '.*\.[ch]' -exec clang-format -i {} \;` to format all C code

Network functions get compiled in two steps.
First, compiling the network function code against the environment interface leads to a static or dynamic library.
This library can be verified with Klint, even without debugging symbols, since it must export symbols for linking with the environment.
Second, compiling the library along with the environment implementation leads to a binary that can be run.
Part of this binary can also be verified with Klint for "full-stack" verification, specifically the driver and the network function, if it is compiled in such a way that these symbols still exist.

An example of end-to-end usage is `Makefile`, which can `compile-X` (compile just nf/X), `build-X` (compile nf/X and link it with a compiled environment),
`verify-X` (using nf/X/spec.py), and `benchmark-X` (basic benchmark of nf/X) for an NF X in `nf/` such as `firewall`.
There's also `compile-all` to just compile all NFs, useful when making changes to the environment interface or the build infrastructure.


## Reproducing paper results

Please see the `experiments` folder readme.


## Writing and verifying your own network function

Start from a copy of `nf/nop`, which is a no-op network function.
Use the existing `nf/*` functions as inspiration.
All environment interactions must use the abstractions in `env/`, especially memory allocations.

To verify it, compile it as documented in `nf/` and use Klint on it as documented in `tool/`.

To write a spec, look at the the documentation in `tool/`, and at existing specs in `nf/` folders.

If you need new data structures, add them in `env/include/structs`, `env/src/structs`.
Then add Klint contracts in `tool/klint/externals` and add them to the `*_externals` dictionaries in `tool/klint/executor.py`.


## Quick start into the project (assumed there is a folder called gits in your home):
```
cd gits/klint/tool/ && source setup-virtualenv.sh

cd gits/klint/nf/bridge
make -f ../Makefile.nf

cd gits/klint/tool
./klint.py libnf ../nf/bridge/libnf.so ../nf/bridge/spec.py
```
Shortcut (executed from the location `klint/tool/`):
```
cd ../nf/ && bash make-one.sh iptables && cd ../tool/ && ./klint.py libnf ../nf/iptables/libnf.so ../nf/iptables/spec.py
```

## Writing documentation
Documentation is made available using the Doxygen framework when making changes to the core `env` use the doxygen standard to comment your code.
