#include "os/clock.h"

#include <fcntl.h>
#include <unistd.h>
// We already have a time_t, don't re-define it
#define __time_t_defined 1
#include <time.h>

#include "arch/tsc.h"
#include "os/log.h"


// Fetch it at startup and store it, to make the time call as fast as possible, it's on the critical path
static uint64_t cpu_freq_numerator;
static uint64_t cpu_freq_denominator;

static uint64_t linux_msr_read(uint64_t index)
{
	int msr_fd = open("/dev/cpu/0/msr", O_RDONLY);
	if (msr_fd == -1) {
		os_fatal("Could not open MSR file; are you root? did you modprobe msr?");
	}

	off_t seek_result = lseek(msr_fd, (off_t) index, SEEK_SET);
	if (seek_result == (off_t) -1) {
		os_fatal("Could not seek into MSR file");
	}

	uint64_t msr = 0;
	long read_result = read(msr_fd, (void*) &msr, sizeof(msr));
	if (read_result != sizeof(msr)) {
		os_fatal("Could not read MSR file");
	}

	return msr;
}

__attribute__((constructor))
static void fetch_tsc_freq(void)
{
	tsc_get_nhz(linux_msr_read, &cpu_freq_numerator, &cpu_freq_denominator);
}


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
