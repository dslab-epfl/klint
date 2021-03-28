#!/bin/sh

for dir in *; do
  if [ -d "$dir" ]; then
    make -C "$dir" -f "$(pwd)/../Makefile.nf" clean
    make -C "$dir" -f "$(pwd)/../Makefile.nf"
  fi
done
