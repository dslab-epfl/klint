#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/clock.h"
#include "os/fail.h"


// Attempts to get a parameter with the given name
bool os_config_get(const char* name, uintmax_t* out_value);


// Gets a required parameter of the given name within the given range, or exits the program if there is no such parameter or if its value is outside the range.
static inline uintmax_t os_config_try_get(const char* name, uintmax_t min, uintmax_t max)
{
	uintmax_t value;
	if (!os_config_get(name, &value)) {
		os_fail("No such value");
	}
	if (min != 0) {
		intmax_t as_signed = (intmax_t) value;
		if (as_signed < (intmax_t) min) {
			os_fail("Value is too small");
		}
	}
	if (value > max) {
		os_fail("Value is too large");
	}
	return value;
}

static inline uint64_t os_config_get_u64(const char* name)
{
	return (uint64_t) os_config_try_get(name, 0, UINT64_MAX);
}

static inline uint32_t os_config_get_u32(const char* name)
{
	return (uint32_t) os_config_try_get(name, 0, UINT32_MAX);
}

static inline uint16_t os_config_get_u16(const char* name)
{
	return (uint16_t) os_config_try_get(name, 0, UINT16_MAX);
}

static inline size_t os_config_get_size(const char* name)
{
	// Special max here for convenience, that's the max for some of our data structures
	return (size_t) os_config_try_get(name, 0, SIZE_MAX / 2 + 1);
}

static inline time_t os_config_get_time(const char* name)
{
	return (time_t) os_config_try_get(name, TIME_MIN, TIME_MAX);
}
