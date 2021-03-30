#include "os/init.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/io.h>

#include "arch/tsc.h"
#include "os/log.h"
#include "os/pci.h"


// Defined in clock.c
extern uint64_t cpu_freq_numerator;
extern uint64_t cpu_freq_denominator;


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


void os_init(void)
{
	// First, call ioperm to make sure future PCI accesses will work
	// We access port 0x80 to wait after an outl, since it's the POST port so safe to do anything with (it's what glibc uses in the _p versions of outl/inl)
	// Also note that since reading an int32 is 4 bytes, we need to access 4 consecutive ports for PCI config/data.
	if (ioperm(0x80, 1, 1) < 0 || ioperm(PCI_CONFIG_ADDR, 4, 1) < 0 || ioperm(PCI_CONFIG_DATA, 4, 1) < 0) {
		os_fatal("PCI ioperms failed");
	}

	// Second, fetch the CPU frequency
	tsc_get_nhz(linux_msr_read, &cpu_freq_numerator, &cpu_freq_denominator);
}
