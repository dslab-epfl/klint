`lb_kern.c` and `common/parsing_helpers.c` are from the CRAB repo, https://github.com/epfl-dcsl/crab/tree/master/middlebox/ebpf, commit 907e7674c6963f259b20e66c33c490e269c31221

The `ip-tcp-parsing-bug.patch` file is the patch from commit `215c7d53821a82b9d6e289ad8267ca9f808911f9` of the CRAB repo, which was made after we reported it privately.

The only modification is to give up on nested VLANs, as this is both unrealistic (e.g. Facebook's Katran errors on them) and cause symbolic execution pains.
In fact, CRAB doesn't even handle them in SYNs (it copies the headers assuming no options or anything)...
See the "MODIFIED:" lines in `common/parsing_helpers.h`
