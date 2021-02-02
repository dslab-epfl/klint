#include "os/clock.h"

#include <time.h>

#include "os/fail.h"


#define MAX_SLEEP_ATTEMPTS 1000


int64_t os_clock_time(void)
{
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return tp.tv_sec * 1000000000ul + tp.tv_nsec;
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
