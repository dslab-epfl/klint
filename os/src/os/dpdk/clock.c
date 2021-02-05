#include "os/clock.h"

#include <rte_cycles.h>


uint64_t os_clock_time_ns(void)
{
	return rte_rdtsc() * 1000000000ull / rte_get_tsc_hz();
}

void os_clock_sleep_ns(uint64_t ns)
{
	rte_delay_us(ns * 1000);
}
