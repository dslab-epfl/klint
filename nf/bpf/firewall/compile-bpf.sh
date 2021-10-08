#!/bin/sh

EXTRA_BPF_CFLAGS='-D ntohs=__builtin_bswap16 -D uint64_t=__u64 --include=linux/udp.h -isystem include' ../compile-bpf.sh xdp_fw_kern.c
