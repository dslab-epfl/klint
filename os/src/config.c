#include "os/config.h"

#include "config/config.h"

#include <inttypes.h>

#include "fail.h"


#define GET_U(width) \
	uint##width##_t os_config_get_u##width(const char* name) \
	{ \
		uintmax_t value; \
		if (!config_get(name, &value)) { \
			fail("No such value: %s", name); \
		} \
		if (value > UINT##width##_MAX) { \
			fail("Value too large: %" PRIuMAX, value); \
		} \
		return (uint##width##_t) value; \
	}

GET_U(16)
GET_U(32)
GET_U(64)

#undef GET_U
