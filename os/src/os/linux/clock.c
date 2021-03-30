#include "os/clock.h"

// We already have a time_t, don't re-define it (first for glibc, second for musl)
#define __time_t_defined 1
#define __DEFINED_time_t 1
#include <time.h>

#include "arch/tsc.h"
#include "os/log.h"


// Fetched at startup (in init.c), to make the time call as fast as possible, it's on the critical path
uint64_t cpu_freq_numerator;
uint64_t cpu_freq_denominator;


time_t os_clock_time_ns(void)
{
	return tsc_get() * cpu_freq_denominator / cpu_freq_numerator;
}


void os_clock_sleep_ns(uint64_t ns)
{
	struct timespec request;
	request.tv_sec = (int64_t) (ns / 1000000000ull);
	request.tv_nsec = (int64_t) (ns % 1000000000ull);

	struct timespec remain;
	int ret = nanosleep(&request, &remain);
	if (ret != 0) {
		// This can only happen due to EFAULT (should be impossible), EINVAL (should also be impossible), or EINTR (should not happen, we don't use signals)
		os_fatal("Could not sleep");
	}
}
