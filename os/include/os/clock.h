#pragma once

#include <stdint.h>

// TODO time is a bottleneck, we need a clever way to avoid invoking it too many times if we can (e.g., when batching)

// Gets the current time in nanoseconds, according to a monotonic clock with an undefined starting point.
uint64_t os_clock_time_ns(void);

// Sleeps for at least the given amount of nanoseconds.
void os_clock_sleep_ns(uint64_t ns);
