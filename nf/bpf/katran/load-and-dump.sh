#!/bin/sh

#EXTRA_BPF_CFLAGS='-D ntohs=__builtin_bswap16 -D uint64_t=__u64 --include=linux/udp.h'
EXTRA_BPF_CFLAGS='-I linux_includes -Wno-compare-distinct-pointer-types' ../load-and-dump.sh balancer_kern.c
