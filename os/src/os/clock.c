#include "os/clock.h"

#include <stdlib.h>
#include <time.h>
#include <x86intrin.h>

#include "os/fail.h"


#define MAX_SLEEP_ATTEMPTS 1000


static int64_t current_time = 0;


int64_t os_clock_time(void)
{
	if (current_time == 0) {
		struct timespec tp;
		clock_gettime(CLOCK_MONOTONIC, &tp);
		current_time = tp.tv_sec * 1000000000ul + tp.tv_nsec;
	}
	return current_time;
}

void os_clock_time_flush(void)
{
	current_time = 0;
}


// TODO remove this, or do something silly but technically correct like returning the time (and pretending we're on a slow CPU)
uint64_t os_clock_cycles(void)
{
	return __rdtsc();
}

// Note that POSIX's "usleep" call, which could be used directly here, was removed in POSIX-2008.
void os_clock_sleep_us(uint64_t microseconds)
{
	struct timespec request;
	request.tv_sec = (int64_t)(microseconds / 1000000);
	request.tv_nsec = (int64_t)(microseconds % 1000000) * 1000;

	for (uint64_t n = 0; n < MAX_SLEEP_ATTEMPTS; n++) {
		// We don't care if we end up sleeping more than requested due to interrupts and restarts.
		// (properly doing it with clock_gettime then clock_nanosleep in absolute time would require handling time overflows; not fun)
		struct timespec remain;
		int ret = nanosleep(&request, &remain);
		if (ret == 0) {
			return;
		}
		// Got interrupted; try again.
		// Other codes cannot happen according to the documentation (memory issue or invalid sec/nsec).
		request.tv_sec = remain.tv_sec;
		request.tv_nsec = remain.tv_nsec;
	}
	os_fail("Could not sleep");
}
