#pragma once

#include <stdint.h>

// TODO can we get rid of time_t altogether?
typedef int64_t time_t;

time_t os_clock_time(void);

// Forces the next os_clock_time read to be uncached
void os_clock_time_flush(void);

// Get the current number of CPU cycles.
uint64_t os_clock_cycles(void);

// Sleeps for at least the given amount of microseconds.
// It is acceptable but inefficient to sleep for more than that.
void os_clock_sleep_us(uint64_t microseconds);


// Proof API
#define malloc_block_times malloc_block_llongs
#define PRED_times llongs
#define chars_to_times chars_to_llongs
