#!/bin/sh

EXTRA_BPF_CFLAGS='-I common -Wno-compare-distinct-pointer-types' ../load-and-dump.sh lb_kern.c
