#!/bin/sh

EXTRA_CFLAGS='-I common -Wno-compare-distinct-pointer-types' ../load-and-dump.sh lb_kern.c
