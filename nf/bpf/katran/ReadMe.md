These files, except `compile-bpf.sh`, were obtained from the Katran project, commit b09ba2caa1239f148556ff04c8d25ba5ec2fd037 of github.com/facebookincubator/katran
They were originally in `katran/lib/bpf/`, except for `linux_includes` which is `katran/lib/linux_includes`.
The original files are Copyright (c) Facebook, Inc. and its affiliates, and distributed under the GPLv2 licence.

Changes:
- Removed a useless "if" that creates many paths in `csum_helpers.h` (see the `REMOVED:` line)
- Removed the use of the `lru_mapping` map, which requires custom BPF loading and which we do not model anyway (see `REMOVED:` in `balancer_maps.h` and `balancer_kern.c`)
- Changed the `fallback_cache` map from `LRU_HASH` to `HASH`, as LRU requires extra modelling due to the way the Linux kernel inlines calls, which we do not have time to do right now
- Replaced `jhash` by a version that returns a random number (sound, but not complete) as the hash result is way too complex for analysis otherwise (original is in `linux_includes/jhash.h.orig`)
