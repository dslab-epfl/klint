# Klint

You'll need Python 3, with all the dependencies from `requirements.txt`; running `. setup.sh` will install them for you on Ubuntu.
Or use an IDE with virtualenv support.

Two layers:
- `kalm` adapts angr to perform exhaustive symbolic execution, and adds some features we need
- `klint` is the actual tool

Compile the NF yourself: for `libnf` verif of the NFs under `../nf`, use `make -f ../Makefile.nf` in the NF's folder;
for `bpf-jited` verif of the NFs under `../nf/bpf`, run `./compile-bpf.sh` in the NF's folder.

The intended entry point is `./klint.py`, use `--help` for usage instructions. Main args you'll be interested in:
- `--export-graphs` (for any target) exports DOT graphs in the `graphs/` output folder corresponding to paths in the code.
  There's one graph per iteration of symbex until a fixed-point is found.
  To visualize, use e.g. `for g in graphs/*.dot ; do dot -Tpng -o $g.png $g ; done` to convert .dot files to PNGs.
- For BPF JITed code, `--havoc-all` to havoc all maps if the code assumes maps are touched by user space. Or `--havoc xxx` to specifically havoc map `xxx`.

Klint is based on angr, so if you want to extend it the angr tutorial is a must: https://docs.angr.io/core-concepts

Klint also has some basic unit tests, run `python -m unittests`

Note that the "instruction limit" mentioned in the paper is not yet supported but should be trivial to add using angr's built-in features.
