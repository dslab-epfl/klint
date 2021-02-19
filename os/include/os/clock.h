#pragma once

#include <stdint.h>


typedef uint64_t time_t;

// To allow containers that store a time to optimize storage; anyway, reaching the end of time would be problematic
#define TIME_INVALID ((time_t) 0xFFFFFFFFFFFFFFFFull)

// For VeriFast; ideally we'd use '((time_t) -1) < 0' but VeriFast doesn't support this
#define IS_TIME_T_SIGNED false


// Gets the current time in nanoseconds, according to a monotonic clock with an undefined starting point.
// TODO time is a bottleneck, we need a clever way to avoid invoking it too many times if we can (e.g., when batching)
time_t os_clock_time_ns(void);
//@ requires emp;
//@ ensures result != TIME_INVALID;

// Sleeps for at least the given amount of nanoseconds.
void os_clock_sleep_ns(uint64_t ns);
//@ requires emp;
//@ ensures emp;
