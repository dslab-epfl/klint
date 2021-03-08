#include "os/clock.h"

#include "arch/msr.h"
#include "arch/tsc.h"


// Fetch it at startup and store it, to make the time call as fast as possible, it's on the critical path
static uint64_t cpu_freq_numerator;
static uint64_t cpu_freq_denominator;

__attribute__((constructor))
static void fetch_tsc_freq(void)
{
	tsc_get_nhz(msr_read, &cpu_freq_numerator, &cpu_freq_denominator);
}


time_t os_clock_time_ns(void)
{
	return tsc_get() * cpu_freq_denominator / cpu_freq_numerator;
}


void os_clock_sleep_ns(uint64_t ns)
{
	time_t target = os_clock_time_ns() + ns;
	while (os_clock_time_ns() != target) {
		// Nothing (TODO: CPU pause?)
	}
}
