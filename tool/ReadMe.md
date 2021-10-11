This is based on angr: https://docs.angr.io/core-concepts

Two layers:
- `kalm` adapts angr to be about exhaustive symbolic execution
- `klint` is the actual tool

You'll need Python 3, with all the dependencies from `requirements.txt`; running `. setup.sh` will install them for you on Linux. Or use an IDE with virtualenv support.

The intended entry point is `./klint.py`, use `--help` for usage instructions.

Compile the NF yourself (using `make -f ../Makefile.nf` in its folder for "libnf" verif, or ./load-and-dump.sh for "bpf-jited" verif).

With `--export-graphs`, use e.g. `for g in graphs/*.dot ; do dot -Tpng -o $g.png $g ; done` to convert .dot files to PNGs

Code structure: <TODO>
