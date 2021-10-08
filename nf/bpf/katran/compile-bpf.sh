#!/bin/sh

EXTRA_BPF_CFLAGS='-I linux_includes -Wno-compare-distinct-pointer-types' ../compile-bpf.sh balancer_kern.c
