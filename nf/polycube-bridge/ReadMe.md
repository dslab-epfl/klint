This file was obtained from the Polycube project, commit 245ed49ab119927055a9dd22120514aa0d34bbce of github.com/polycube-network/polycube
The original file is Copyright 2018 The Polycube Authors, Licensed under the Apache License, Version 2.0.

It was modified in the following ways:
- Replaced the `timestamp` table, intended to be updated by userspace, with a call to `bpf_ktime_get_boot_ns`.
- Replaced the object-oriented BCC table method calls with standard BPF ones.
- Made `handle_rx` non-static.

No other changes were performed; comments are from the original authors.
