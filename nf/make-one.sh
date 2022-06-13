#!/bin/bash
if [[ ! -d "$1"  ]]; then
  echo "Directory does not exist"
  exit 1
fi
make -C "$1" -f "$(pwd)/Makefile.nf"