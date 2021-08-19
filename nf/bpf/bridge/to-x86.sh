#!/bin/sh

THIS_DIR="$(dirname $(readlink -f $0))"

EXTRA_CFLAGS="-isystem . --include $THIS_DIR/../../../os/include/compat/polycube.h" ../to-x86.sh Simplebridge_dp.c
