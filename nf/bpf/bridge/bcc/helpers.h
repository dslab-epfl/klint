#pragma once

#define BPF_TABLE(_, key, value, name, size) struct bpf_map_def name = { .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(key), .value_size = sizeof(value), .max_entries = size }
