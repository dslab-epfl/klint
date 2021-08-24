#!/bin/sh

THIS_DIR="$(dirname $(readlink -f $0))"

EXTRA_BPF_CFLAGS="-isystem . -isystem $THIS_DIR/../../../os/include/compat/" ../load-and-dump.sh Simplebridge_dp.c
