These files were obtained from the Katran project, commit b91b67d3714fa6f8507cfbf2b3a8e69e9c5999f4 of https://github.com/facebookincubator/katran

They were originally in katran/lib/bpf/

The original files are Copyright (c) Facebook, Inc. and its affiliates, and distributed under the GPLv2 licence.

They were modified in the following ways:
- Removed files unrelated to `balancer_kern.c`
- Replaced Linux header includes with our equivalent ones.
- Renamed `balancer_ingress` to `xdp_main`
- Added `init.c`
