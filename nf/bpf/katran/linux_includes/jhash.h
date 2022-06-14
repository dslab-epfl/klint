#pragma once

static inline u32 jhash(const void* key, u32 length, u32 initval) { return bpf_get_prandom_u32(); }

static inline u32 jhash_2words(u32 a, u32 b, u32 initval) { return bpf_get_prandom_u32(); }
