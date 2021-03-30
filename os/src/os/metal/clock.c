#include "os/clock.h"

#include "arch/tsc.h"


// Fetched at startup (in init.c), to make the time call as fast as possible, it's on the critical path
uint64_t cpu_freq_numerator;
uint64_t cpu_freq_denominator;


time_t os_clock_time_ns(void)
//@ requires emp;
//@ ensures result != TIME_MAX;
{
	//@ assume(false); // Nothing to prove here, this depends on hardware details
	return tsc_get() * cpu_freq_denominator / cpu_freq_numerator;
}


void os_clock_sleep_ns(uint64_t ns)
//@ requires emp;
//@ ensures emp;
{
	//@ assume(false); // Nothing to prove here, this depends on hardware details
	time_t target = os_clock_time_ns() + ns;
	while (os_clock_time_ns() != target) {
		// Nothing (TODO: CPU pause?)
	}
}
