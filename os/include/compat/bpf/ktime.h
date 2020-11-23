#pragma once

#include "os/clock.h"

static inline uint64_t bpf_ktime_get_boot_ns(void)
{
	return (uint64_t) os_clock_time();
}
