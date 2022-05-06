All paths in this document are relative to the root of the repo.
Please see the paper for the exact hardware we used; but the relative perf results should hold anywhere.
You will need an 82599 NIC, though, since that's the only one we have a verifiable driver for.

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

Run `./verif-all.sh`, which should take <10min.
(You can also run `./verif.sh` in `env/` to verify the data structures and memory allocator)

## Figure 5 and Table 2

Follow the instructions at the end of this document for the prerequisites.
You'll also need `musl-gcc`, since we use musl to statically link the entire binary including libc.

Run `./bench-all.sh` to create the data, which will take <2h.

Then for Figure 5, you need Python with the dependencies from requirements.txt; you can run `. setup-virtualenv-graphing.sh` on Ubuntu.
Run `./graph-tput-vs-lat.py Bridge bridge-vigor-dpdk bridge-vigor-tinynf bridge-click bridge-dpdk bridge-ours`.

For Table 2, run `./tabulate-perf.sh`

## Table 3

This is only for illustration purposes.



## Benchmark prerequisites

To run the benchmarks, you need two machines running Linux:
- A "device under test" machine with two Intel 82599ES NICs on the same NUMA node, from which you will run the experiment scripts
- A "tester" machine connected to the other one by two 10G Ethernet cables

As a first step, go to the `benchmarking` folder at the root of this repository, and follow the first list in the instructions ("Get ahold of two machines...").

Assuming a 2-CPU machine whose second CPU has cores 8 to 15, we recommend the following Linux kernel parameters for the two machines (add to `GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub`):
- `nosmt`: Disable HyperThreading, to avoid contention among threads in benchmarks
- `intel_iommu=off`: Disable the IOMMU, we don't need it
- `hugepages=4096`: preallocate 4K hugepages of the default 2MB size
- `isolcpus=8-15 nohz_full=8-15 rcu_nocbs=8-15`: Isolate the second CPU entirely
- `nosoftlockup`: No backtraces for processes that appear to hang, such as NFs that run for a long time
- `processor.ignore_ppc=1`: Do not listen to the BIOS about CPU frequency limitations
- `pcie_aspm=off`: Force PCIe devices to run at full power
- `intel_idle.max_cstate=0 processor.max_cstate=0`: Disable CPU low power states
- `idle=poll cpuidle.off=1`: Force the CPU to spin instead of using waits for idling
- `intel_pstate=disable`: Allow Linux to set the CPU frequency via `cpupower` instead of letting the Intel driver choose
