#!/bin/sh

EXTRA_CFLAGS='-I common -Wno-compare-distinct-pointer-types' ../to-x86.sh lb_kern.c
