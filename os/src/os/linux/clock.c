#include "os/clock.h"

#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include <x86intrin.h>

#include "os/fail.h"


static uint64_t cpu_freq; // in 100s of MHz

__attribute__((constructor))
static void fetch_cpu_freq(void)
{
	// We're on Ivy Bridge
	// TODO make this more general? or just fail if not SB/IB/HW/BW given the cite below?
	// Intel manual
	// "18.7.3.1 For Intel® Processors Based on Microarchitecture Code Name Sandy Bridge, Ivy Bridge, Haswell and Broadwell:
	//  The scalable bus frequency is encoded in the bit field MSR_PLATFORM_INFO[15:8] and the nominal TSC frequency can be determined by multiplying this number by a bus speed of 100 MHz."
	// MSR_PLATFORM_INFO is 0xCE
	int msr_fd = open("/dev/cpu/0/msr", O_RDONLY);
	if (msr_fd == -1) {
		os_fail("Could not open MSR file; are you root? did you modprobe msr?");
	}

	off_t seek_result = lseek(msr_fd, 0xCE, SEEK_SET);
	if (seek_result == (off_t) -1) {
		os_fail("Could not seek into MSR file");
	}

	uint64_t msr = 0;
	long read_result = read(msr_fd, (void*) &msr, sizeof(msr));
	if (read_result != sizeof(msr)) {
		os_fail("Could not read MSR file");
	}

	cpu_freq = ((msr >> 8) & 0xFF);
}


uint64_t os_clock_time_ns(void)
{
	return __rdtsc() * 10 / cpu_freq; // freq is in 100s of MHz so tsc/freq is in 1/100us, thus we multiply by 10 for ns
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
