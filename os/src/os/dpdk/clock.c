#include "os/clock.h"

#include <time.h>

#include <rte_cycles.h>


int64_t os_clock_time(void)
{
	// DPDK has rte_rdtsc, but it must be divided by a frequency, and DPDK uses very imprecise computations to do that on old CPUs like ours
	// So use the POSIX way instead... kind of defeats the purpose of a "DPDK" OS, but oh well, better that than a "fast" but wrong clock.
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return tp.tv_sec * 1000000000ul + tp.tv_nsec;
}

void os_clock_sleep_us(uint64_t microseconds)
{
	rte_delay_us(microseconds);
}
