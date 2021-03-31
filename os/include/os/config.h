#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/clock.h"


// Attempts to get a parameter with the given name, or returns false
bool os_config_try_get(const char* name, uintmax_t* out_value);
//@ requires [?f]*name |-> _ &*& *out_value |-> _;
//@ ensures [f]*name |-> _ &*& *out_value |-> _;


// Gets a parameter of the given name within the given range (both inclusive), or returns false
static inline bool os_config_get(const char* name, uintmax_t min, uintmax_t max, uintmax_t* out_value)
{
	if (!os_config_try_get(name, out_value)) {
		return false;
	}
	if (min != 0) {
		intmax_t as_signed = (intmax_t) *out_value;
		if (as_signed < (intmax_t) min) {
			return false;
		}
	}
	return *out_value <= max;
}

static inline bool os_config_get_u64(const char* name, uint64_t* out_value)
{
	uintmax_t value;
	if (!os_config_get(name, 0, UINT64_MAX, &value)) {
		return false;
	}
	*out_value = (uint64_t) value;
	return true;
}

static inline bool os_config_get_u32(const char* name, uint32_t* out_value)
{
	uintmax_t value;
	if (!os_config_get(name, 0, UINT32_MAX, &value)) {
		return false;
	}
	*out_value = (uint32_t) value;
	return true;
}

static inline bool os_config_get_u16(const char* name, uint16_t* out_value)
{
	uintmax_t value;
	if (!os_config_get(name, 0, UINT16_MAX, &value)) {
		return false;
	}
	*out_value = (uint16_t) value;
	return true;
}

static inline bool os_config_get_size(const char* name, size_t* out_value)
{
	// Special max here for convenience, that's the max for some of our data structures
	uintmax_t value;
	if (!os_config_get(name, 0, SIZE_MAX / 64, &value)) {
		return false;
	}
	*out_value = (size_t) value;
	return true;
}

static inline bool os_config_get_time(const char* name, time_t* out_value)
{
	uintmax_t value;
	if (!os_config_get(name, TIME_MIN, TIME_MAX, &value)) {
		return false;
	}
	*out_value = (time_t) value;
	return true;
}
