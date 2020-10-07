#pragma once

#include <stdint.h>
#include "clock.h"

// Gets a required parameter of the given name, or exits the program if there is no such parameter or if its value is incompatible.
uint16_t os_config_get_u16(const char* name);
uint32_t os_config_get_u32(const char* name);
uint64_t os_config_get_u64(const char* name);
time_t os_config_get_time(const char* name);
