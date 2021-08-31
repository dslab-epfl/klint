#!/bin/sh

# TODO this is awful, rewrite

for dir in *; do
  if [ "$dir" = 'bpf' ]; then
    for dir2 in "$dir/"*; do
      if [ -d "$dir2" ]; then
        make -C "$dir2" -f "$(pwd)/Makefile.nf"
      fi
    done
  elif [ -d "$dir" ]; then
    make -C "$dir" -f "$(pwd)/Makefile.nf"
  fi
done
