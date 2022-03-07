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
