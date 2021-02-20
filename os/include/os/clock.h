#pragma once

#include <stdint.h>


typedef uint64_t time_t;

#define TIME_MAX UINT64_MAX
#define TIME_MIN 0


// Gets the current time in nanoseconds, according to a monotonic clock with an undefined starting point.
// Do not ever return TIME_MAX to allow containers that store a time to optimize storage; anyway, reaching the end of time would be problematic
// TODO time is a bottleneck, we need a clever way to avoid invoking it too many times if we can (e.g., when batching)
time_t os_clock_time_ns(void);
//@ requires emp;
//@ ensures result != TIME_MAX;

// Sleeps for at least the given amount of nanoseconds.
void os_clock_sleep_ns(uint64_t ns);
//@ requires emp;
//@ ensures emp;
