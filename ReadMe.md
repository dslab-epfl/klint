- `os` is the NFOS
- `config` is `libconfig`, which allows one to define a config as a file with trivial parsing code (see `build-and-run.sh` for an example config)
- `nat` and friends are NFs
- `Makefile.base` is the common Makefile between NFOS and NFs
- `Makefile.nf` is the Makefile for NFs (make them with `make -f ../Makefile.nf`)
