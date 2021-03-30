#include "os/init.h"

#include "arch/msr.h"
#include "arch/tsc.h"


// For clock.h
uint64_t cpu_freq_numerator;
uint64_t cpu_freq_denominator;


void os_init(void)
{
	tsc_get_nhz(msr_read, &cpu_freq_numerator, &cpu_freq_denominator);
}
