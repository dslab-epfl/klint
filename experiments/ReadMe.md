## Figure 1

This is a high-level overview of the split between the `nf/` and `env/` folders at the root of this repo: NFs and environment.

## Figure 2

This is only for illustration purposes.

## Listing 1

This is only for illustration purposes.
Actual contracts are in VeriFast form in `env/include/structs` and in Python form in `tool/klint/externals`.

## Figure 3

This is only for illustration purposes.

## Figure 4

This is an illustration of the implementation of `set` in `tool/klint/ghostmaps.py`.

## Listing 2

This is the contents of the `nf/firewall/spec-small.py` file, which can be used with Klint as-is.

## Table 1

Run `./verif-all.sh`.
(You can also run `./verif.sh` in `env/` to verify the data structures and memory allocator)

## Figure 5 and Table 2

You'll need `musl-gcc`, since we use musl to statically link the entire binary including libc.
Run:

```
./bench-all.sh
# Figure 5
# For this step you need Python with the dependencies from requirements.txt; you can run `. setup-virtualenv-graphing.sh` on Ubuntu
./graph-tput-vs-lat.py Bridge bridge-vigor-dpdk bridge-vigor-tinynf bridge-click bridge-dpdk bridge-ours
# Table 2
./tabulate-perf.sh
```

## Table 3

This is only for illustration purposes.
