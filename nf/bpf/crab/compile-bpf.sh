#!/bin/sh

# Define RAND so we don't have to bother havocing the map used in the other case
EXTRA_BPF_CFLAGS='-D RAND -I common -Wno-compare-distinct-pointer-types' ../compile-bpf.sh lb_kern.c
