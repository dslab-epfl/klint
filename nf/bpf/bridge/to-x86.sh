#!/bin/sh

THIS_DIR="$(dirname $(readlink -f $0))"

EXTRA_CFLAGS="-isystem . -isystem $THIS_DIR/../../../os/include/compat/" ../to-x86.sh Simplebridge_dp.c
