#pragma once

#include <x86intrin.h>


uint64_t tsc_get(void)
{
	return __rdtsc();
}

// Gets the frequency of the timestamp counter in nanohertz as a rational number, given an MSR-reading function
void tsc_get_nhz(uint64_t (*read_msr)(uint64_t), uint64_t* out_numerator, uint64_t* out_denominator)
{
	// We're on Ivy Bridge
	// TODO make this more general? or just fail if not SB/IB/HW/BW given the cite below?
	// Intel manual
	// "18.7.3.1 For Intel® Processors Based on Microarchitecture Code Name Sandy Bridge, Ivy Bridge, Haswell and Broadwell:
	//  The scalable bus frequency is encoded in the bit field MSR_PLATFORM_INFO[15:8] and the nominal TSC frequency can be determined by multiplying this number by a bus speed of 100 MHz."
	// MSR_PLATFORM_INFO is 0xCE
	uint64_t msr = read_msr(0xCE);
	*out_numerator = (msr >> 8) & 0xFF;
	*out_denominator = 10;
}
