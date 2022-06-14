# Network functions

NFs directly in this folder are the ones we wrote.
Those in `bpf/` are BPF NFs we adapted.

`Makefile.nf` is the shared Makefile for the NFs we wrote, use it by passing `-f` to `make` (i.e., NFs directly use that Makefile, even if they have their own for extra stuff).

`nop` is a no-op for testing and benchmarking purposes.

`bridge`, `firewall`, `nat`, `maglev` `policer`, `[rust-]router` are originally from the NSDI paper.

`dhcp`, `dns`, and `iptables*` were written by students afterwards.
