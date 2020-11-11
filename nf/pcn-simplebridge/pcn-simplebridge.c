// This file was obtained from the Polycube project, commit 245ed49ab119927055a9dd22120514aa0d34bbce of github.com/polycube-network/polycube
// It was originally named src/services/pcn-simplebridge/src/Simplebridge_dp.c
// The original file is Copyright 2018 The Polycube Authors, Licensed under the Apache License, Version 2.0.
// It was modified in the following ways:
// - Removed `pcn_log` calls (we do not need logging, and pcn_log has advanced formats we do not support).
// - Replaced the `timestamp` table, intended to be updated by userspace, with a call to `bpf_ktime_get_boot_ns`.
// - Replaced the object-oriented BPF tables functional-style ones (since we compile as C, not via BPF).
// - Replaced the BCC and Linux headers with our equivalent ones.
// - Replaced non-standard C constructs with their standard equivalents, such as using u8* instead of void* for pointers used in arithmetic
// - Fixed C constructs that cause warnings, such as removing unused labels
// No other changes were performed; comments are from the original authors.

#ifndef FDB_TIMEOUT
#define FDB_TIMEOUT 300
#endif

#include "bpfutil/ktime.h"
#include "bpfutil/polycube.h"
#include "bpfutil/table.h"
#include "bpfutil/types.h"

#define REASON_FLOODING 0x01

struct fwd_entry {
  u32 timestamp;
  u32 port;
} __attribute__((packed, aligned(8)));

BPF_TABLE(hash, __be64, struct fwd_entry, fwdtable, 1024)

struct eth_hdr {
  __be64 dst : 48;
  __be64 src : 48;
  __be16 proto;
} __attribute__((packed));

static __always_inline u32 time_get_sec() {
  return bpf_ktime_get_boot_ns() / ((u64) 1000 * 1000 * 1000);
}

static __always_inline int handle_rx(struct CTXTYPE *ctx,
                                     struct pkt_metadata *md) {
  u8 *data = (u8 *)(long)ctx->data;
  u8 *data_end = (u8 *)(long)ctx->data_end;
  struct eth_hdr *eth = (struct eth_hdr *) data;

  if (data + sizeof(*eth) > data_end)
    return RX_DROP;

  u32 in_ifc = md->in_port;

  // LEARNING PHASE
  __be64 src_key = eth->src;
  u32 now = time_get_sec();

  struct fwd_entry *entry = bpfutil_table_lookup(&fwdtable, &src_key);

  if (!entry) {
    struct fwd_entry e;  // used to update the entry in the fdb

    e.timestamp = now;
    e.port = in_ifc;

    bpfutil_table_update(&fwdtable, &src_key, &e);
  } else {
    entry->port = in_ifc;
    entry->timestamp = now;
  }

  // FORWARDING PHASE: select interface(s) to send the packet
  __be64 dst_mac = eth->dst;
  // lookup in forwarding table fwdtable
  entry = bpfutil_table_lookup(&fwdtable, &dst_mac);
  if (!entry) {
    goto DO_FLOODING;
  }

  u64 timestamp = entry->timestamp;

  // Check if the entry is still valid (not too old)
  if ((now - timestamp) > FDB_TIMEOUT) {
    bpfutil_table_delete(&fwdtable, &dst_mac);
    goto DO_FLOODING;
  }

  u32 dst_interface = entry->port;  // workaround for verifier

  // HIT in forwarding table
  // redirect packet to dst_interface

  /* do not send packet back on the ingress interface */
  if (dst_interface == in_ifc) {
    return RX_DROP;
  }

  return pcn_pkt_redirect(ctx, md, dst_interface);

DO_FLOODING:
  pcn_pkt_controller(ctx, md, REASON_FLOODING);
  return RX_DROP;
}
