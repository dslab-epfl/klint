#!/bin/sh

EXTRA_CFLAGS='-D ntohs=__builtin_bswap16 -D uint64_t=__u64 --include=linux/udp.h' ../load-and-dump.sh xdp_fw_kern.c
