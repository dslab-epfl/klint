#!/bin/sh

EXTRA_BPF_CFLAGS='-Iinclude' ../load-and-dump.sh xdp_filter.c
