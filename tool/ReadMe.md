This is based on angr: https://docs.angr.io/core-concepts

You'll need Python 3, with all the dependencies from `requirements.txt`; running `. setup.sh` will install them for you on Linux. Or use an IDE with virtualenv support.

The intended entry point is `main.py`; compile the NF yourself (using `make -f ../../Makefile.nf` in its folder) then set the last string in the last line to verify an NF.

Code structure: <TODO>