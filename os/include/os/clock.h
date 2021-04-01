#pragma once

#include <stdint.h>

#include "arch/tsc.h"


typedef uint64_t time_t;

#define TIME_MAX UINT64_MAX
#define TIME_MIN 0

// Fetched at startup by the OS, to make the time call as fast as possible, it's on the critical path
extern uint64_t cpu_freq_numerator;
extern uint64_t cpu_freq_denominator;

// Gets the current time in nanoseconds, according to a monotonic clock with an undefined starting point.
// Can be safely assumed to never return TIME_MAX, allowing containers that store a time to optimize storage; anyway, reaching the end of time would be problematic
static inline time_t os_clock_time_ns(void)
{
	return tsc_get() * cpu_freq_denominator / cpu_freq_numerator;
}


// Sleeps for at least the given amount of nanoseconds.
// TODO This function would not be necessary if symbex could handle loops;
//      it could be implemented inline as a busy-waiting loop with a "pause" hint
void os_clock_sleep_ns(uint64_t ns);
//@ requires emp;
//@ ensures emp;
