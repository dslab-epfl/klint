#include "os/clock.h"
#include "private/clock.h"

#include <time.h>


static int64_t current_time = 0;


// --- Internal API ---

void os_clock_flush(void)
{
	current_time = 0;
}


// --- Public API ---

int64_t os_clock_time(void)
{
	if (current_time == 0) {
		struct timespec tp;
		clock_gettime(CLOCK_MONOTONIC, &tp);
		current_time = tp.tv_sec * 1000000000ul + tp.tv_nsec;
	}
	return current_time;
}
