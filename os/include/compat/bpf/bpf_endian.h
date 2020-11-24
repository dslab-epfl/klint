#pragma once

#include "compat/uapi/linux/in.h"

#define bpf_htons htons
#define bpf_htonl htonl
#define bpf_ntohs ntohs
