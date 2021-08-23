The `Simplebridge_dp.c` file was obtained from the Polycube project, commit 245ed49ab119927055a9dd22120514aa0d34bbce of github.com/polycube-network/polycube
It was originally in src/services/pcn-simplebridge/src/. 
The original file is Copyright 2018 The Polycube Authors, Licensed under the Apache License, Version 2.0.

It was modified in the following ways:
- Added an include for our `polycube.h` stub
- Replaced the `timestamp` table, intended to be updated by userspace, with a call to `bpf_ktime_get_ns`.
- Replaced the object-oriented BCC table method calls with standard BPF ones.
- Added `bcc/` headers with just the minimum needed to compile
- Replaced `md->in_port` for `in_ifc` by `ctx->ingress_ifindex`, otherwise the Linux BPF verifier was complaining
- Added a `main.c` file

No other changes were performed; comments are from the original authors.