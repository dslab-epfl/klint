#pragma once

#include "os/time.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Attempts to get a parameter with the given name
 *
 * @param name name of the parameter
 * @param out_value value of the parameter
 * @return true parameter was successfully retrieved
 * @return false failed to retrieve the parameter
 */
bool os_config_try_get(const char* name, uint64_t* out_value);
//@ requires [?f]*name |-> _ &*& *out_value |-> _;
//@ ensures [f]*name |-> _ &*& *out_value |-> _;

/**
 * @brief Gets a parameter of the given name within the given range (both inclusive)
 *
 * @param name name of the value
 * @param min
 * @param max
 * @param out_value
 * @return true parameter retrieved
 * @return false failed to retrieve the parameter
 */
static inline bool os_config_get(const char* name, uint64_t min, uint64_t max, uint64_t* out_value)
{
	if (!os_config_try_get(name, out_value)) {
		return false;
	}
	if (min != 0) {
		int64_t as_signed = (int64_t) *out_value;
		if (as_signed < (int64_t) min) {
			return false;
		}
	}
	return *out_value <= max;
}

/**
 * @brief Attempts to get a unisigned 64 bit integer from the config file
 *
 * @param name name of the value
 * @param out_value
 * @return true
 * @return false
 */
static inline bool os_config_get_u64(const char* name, uint64_t* out_value)
{
	uint64_t value;
	if (!os_config_get(name, 0, UINT64_MAX, &value)) {
		return false;
	}
	*out_value = (uint64_t) value;
	return true;
}

/**
 * @brief Attempts to get a unisigned 32 bit integer
 *
 * @param name name of the value
 * @param out_value
 * @return true
 * @return false
 */
static inline bool os_config_get_u32(const char* name, uint32_t* out_value)
{
	uint64_t value;
	if (!os_config_get(name, 0, UINT32_MAX, &value)) {
		return false;
	}
	*out_value = (uint32_t) value;
	return true;
}

/**
 * @brief Attempts to get a unisigned 16 bit integer
 *
 * @param name name of the value
 * @param out_value
 * @return true
 * @return false
 */
static inline bool os_config_get_u16(const char* name, uint16_t* out_value)
{
	uint64_t value;
	if (!os_config_get(name, 0, UINT16_MAX, &value)) {
		return false;
	}
	*out_value = (uint16_t) value;
	return true;
}

/**
 * @brief Attempts to get a value of type size_t
 *
 * @param name name of the value
 * @param out_value
 * @return true
 * @return false
 */
static inline bool os_config_get_size(const char* name, size_t* out_value)
{
	// Special max here for convenience, that's the max for some of our data structures
	uint64_t value;
	if (!os_config_get(name, 0, SIZE_MAX / 64, &value)) {
		return false;
	}
	*out_value = (size_t) value;
	return true;
}

/**
 * @brief Attempts to get a value of type time_t
 *
 * @param name
 * @param out_value
 * @return true
 * @return false
 */
static inline bool os_config_get_time(const char* name, time_t* out_value)
{
	uint64_t value;
	if (!os_config_get(name, TIME_MIN, TIME_MAX, &value)) {
		return false;
	}
	*out_value = (time_t) value;
	return true;
}
