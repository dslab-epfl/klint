#!/bin/sh

EXTRA_BPF_CFLAGS='-Iinclude' ../compile-bpf.sh xdp_filter.c
