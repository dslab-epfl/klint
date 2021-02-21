#include "os/clock.h"

#include <rte_cycles.h>
// HACK: Only way to get the TSC frequency with DPDK without depending on rte_eal_init having been called :/
// We could do it in the time call, but that's on the critical path and would bias perf comparisons, so better do this
#include <../../lib/librte_eal/common/eal_private.h>

#include "os/error.h"


// Otherwise the tsc*1e9/hz overflows (and doing tsc*(1e9/hz) would underflow the hz part)
static uint64_t freq_numerator;
static uint64_t freq_denominator;

__attribute__((constructor))
static void fetch_tsc_freq(void)
{
	freq_numerator = get_tsc_freq_arch();
	if (freq_numerator == 0) {
		os_fatal("Could not get TSC freq");
	}
	freq_denominator = 1000000000ull;
	while (freq_numerator % 10 == 0) {
		freq_numerator = freq_numerator / 10;
		freq_denominator = freq_denominator / 10;
	}
}


uint64_t os_clock_time_ns(void)
{
	return rte_rdtsc() * freq_denominator / freq_numerator;
}

void os_clock_sleep_ns(uint64_t ns)
{
	rte_delay_us(ns * 1000);
}
