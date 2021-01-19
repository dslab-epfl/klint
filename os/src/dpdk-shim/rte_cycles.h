#pragma once

#include "os/clock.h"


static inline uint64_t rte_get_tsc_cycles(void)
{
	// TODO: Is this REALLY necessary? Or can we os_fail("nope") and not have to expose this in include/os?
	return os_clock_cycles();
}
