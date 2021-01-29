#pragma once

#include <stdint.h>

// TODO os_clock_time is a bottleneck, we need a clever way to avoid invoking it too many times if we can (e.g., when batching)

// TODO can we get rid of time_t altogether?
typedef int64_t time_t;

time_t os_clock_time(void);

// Sleeps for at least the given amount of microseconds.
// It is acceptable but inefficient to sleep for more than that.
void os_clock_sleep_us(uint64_t microseconds);


// Proof API
#define malloc_block_times malloc_block_llongs
#define PRED_times llongs
#define chars_to_times chars_to_llongs
