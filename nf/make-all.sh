#!/bin/sh
# Compiles all NFs.

for dir in *; do
  if [ "$dir" = 'bpf' ]; then
    for dir2 in "$dir/"*; do
      if [ -d "$dir2" ]; then
        cd "$dir2"
          ./compile-bpf.sh
        cd -
      fi
    done
  elif [ -d "$dir" ]; then
    make -C "$dir" -f "$(pwd)/Makefile.nf"
  fi
done
