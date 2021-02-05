#include "os/clock.h"

#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "arch/tsc.h"

#include "os/fail.h"


static uint64_t cpu_freq_numerator;
static uint64_t cpu_freq_denominator;

static uint64_t linux_read_msr(uint64_t index)
{
	int msr_fd = open("/dev/cpu/0/msr", O_RDONLY);
	if (msr_fd == -1) {
		os_fail("Could not open MSR file; are you root? did you modprobe msr?");
	}

	off_t seek_result = lseek(msr_fd, (off_t) index, SEEK_SET);
	if (seek_result == (off_t) -1) {
		os_fail("Could not seek into MSR file");
	}

	uint64_t msr = 0;
	long read_result = read(msr_fd, (void*) &msr, sizeof(msr));
	if (read_result != sizeof(msr)) {
		os_fail("Could not read MSR file");
	}

	return msr;
}

__attribute__((constructor))
static void fetch_cpu_freq(void)
{
	tsc_get_nhz(linux_read_msr, &cpu_freq_numerator, &cpu_freq_denominator);
}


uint64_t os_clock_time_ns(void)
{
	return tsc_get() * cpu_freq_denominator / cpu_freq_numerator; // freq is in 100s of MHz so tsc/freq is in 1/100us, thus we multiply by 10 for ns
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
		os_fail("Could not sleep");
	}
}
