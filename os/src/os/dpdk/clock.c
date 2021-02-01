#include "os/clock.h"

#include <rte_cycles.h>


int64_t os_clock_time(void)
{
	return rte_rdtsc() / rte_get_tsc_hz();
}

void os_clock_sleep_us(uint64_t microseconds)
{
	rte_delay_us(microseconds);
}
