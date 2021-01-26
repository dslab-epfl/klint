#pragma once

#include "os/fail.h"

#include <stdbool.h>
#include <stdint.h>

// Attempts to get a parameter with the given name
bool os_config_get(const char* name, uintmax_t* out_value);

// Gets a required parameter of the given name, or exits the program if there is no such parameter or if its value is incompatible.
#define OS_GET_U(width) \
	static inline uint##width##_t os_config_get_u##width(const char* name) \
	{ \
		uintmax_t value; \
		if (!os_config_get(name, &value)) { \
			os_fail("No such value"); \
		} \
		if (value > UINT##width##_MAX) { \
			os_fail("Value too large"); \
		} \
		return (uint##width##_t) value; \
	}

OS_GET_U(16)
OS_GET_U(32)
OS_GET_U(64)

#undef OS_GET_U
