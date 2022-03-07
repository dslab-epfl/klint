This is the artifact for the paper "Automated Verification of Network Function Binaries" presented at NSDI'22.


## Repository structure

- `benchmarking` contains the scripts for benchmarks (building upon those from the TinyNF artifact) 
- `experiments` contains the scripts to reproduce the results in the paper
- `nf` contains the network functions we wrote or adapted
- `env` contains the environment abstractions for network functions and implementations of these abstractions
- `tool` contains the Klint tool
- `Makefile.base` is the common Makefile for all C code


## Reproducing paper results

Please see the `experiments` folder readme.


## Writing and verifying your own network function

Start from a copy of `nf/nop`, which is a no-op network function.
Use the existing `nf/*` functions as inspiration.
All environment interactions must use the abstractions in `env/`, especially memory allocations.

To verify it, compile it as documented in `nf/` and use Klint on it as documented in `tool/`.

If you need new data structures, add them in `env/include/structs`, `env/src/structs`.
Then add Klint contracts in `tool/klint/externals` and add them to the `*_externals` dictionaries in `tool/klint/executor.py`.
