These files, except `compile-bpf.sh`, were obtained from the Suricata project, commit ca760e305cd74933b685b1bd5be795b24a7d94a7 of github.com/OISF/suricata
They were originally in `ebpf/`.
They are distributed under the GPLv2 licence.

Changes:
- Set `USE_PERCPU_HASH` and `GOT_TX_PEER` to 0 as we do not handle this functionality yet
- Replaced `SuperFastHash` by a version that returns a random number (sound, but not complete) as the hash result is way too complex for analysis otherwise (original is in `hash_func01.h.orig`)
