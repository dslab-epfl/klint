#include "os/clock.h"

#include <rte_cycles.h>


// Same idea as the linux impl
uint64_t freq_numerator;
uint64_t freq_denominator;


time_t os_clock_time_ns(void)
{
	return rte_rdtsc() * freq_denominator / freq_numerator;
}

void os_clock_sleep_ns(uint64_t ns)
{
	rte_delay_us(ns * 1000);
}
