You'll need `musl-gcc` for the performance experiment, since we use musl to statically link the entire binary including libc.

```
./bench-all.sh
./graph-tput-vs-lat.py Bridge bridge-vigor-dpdk bridge-vigor-tinynf bridge-click bridge-dpdk bridge-ours
./tabulate-perf.sh
```
