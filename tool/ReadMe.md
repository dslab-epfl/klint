This is based on angr: https://docs.angr.io/core-concepts

You'll need Python 3, with all the dependencies from `requirements.txt`; `. setup.sh` script can install them for you on Linux. Or use an IDE with virtualenv support.

The intended entry point is `executors/nf/vigor.py`; compile the NF yourself (using `make -f ../Makefile.nf` in its folder) then set the last string in the last line to verify an NF.
Currently the NAT takes ~10min to verify, even on a laptop.

Code structure:
- `executors/binary`:
  - `ghost_maps` is an implementation of the "ghost maps" idea
  - `memory*` implement partly-symbolic memory including VeriFast-like fractions; symbolic memory accesses are assumed to be of the form (base + index) where base was allocated through us
  - `externals` contains models for all OS calls
  - `bitsizes`, `cast`, `utils` contain utilities
  - `clock` contains a special clock implementation (would be nice if we could remove it...)
  - `executor` contains some code to make angr behave the way we want
  - `metadata`, `path`, `plugin_dummy` are useful plugins
- `executors/nf`:
  - `defs` is obsolete
  - `vigor` is obsolete, but serves as a decent entry point
  - `executor` is a little bit obsolete, but mostly serves as the general "compose everything else" method
- `executory/python` is obsolete (it'll be for specifications)