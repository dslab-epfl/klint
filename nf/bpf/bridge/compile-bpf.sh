#!/bin/sh

THIS_DIR="$(dirname $(readlink -f $0))"

EXTRA_BPF_CFLAGS="-isystem include" ../compile-bpf.sh Simplebridge_dp.c
