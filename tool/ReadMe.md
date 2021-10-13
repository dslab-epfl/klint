This is based on angr: https://docs.angr.io/core-concepts

Two layers:
- `kalm` adapts angr to be about exhaustive symbolic execution
- `klint` is the actual tool

You'll need Python 3, with all the dependencies from `requirements.txt`; running `. setup.sh` will install them for you on Linux. Or use an IDE with virtualenv support.

Compile the NF yourself: for `libnf` verif of the NFs under `../nf`, use `make -f ../Makefile.nf` in the NF's folder; for `bpf-jited` verif of the NFs under `../nf/bpf`, run `./load-and-dump.sh` in the NF's folder.

The intended entry point is `./klint.py`, use `--help` for usage instructions. Main args you'll be interested in:
- `--export-graphs` (for any target) exports DOT graphs in the `graphs/` output folder corresponding to paths in the code.
  There's one graph per iteration of symbex until a fixed-point is found.
  To visualize, use e.g. `for g in graphs/*.dot ; do dot -Tpng -o $g.png $g ; done` to convert .dot files to PNGs.
- For BPF JITed code, `--havoc-all` to havoc all maps if the code assumes maps are touched by user space. Or `--havoc xxx` to specifically havoc map `xxx`.
