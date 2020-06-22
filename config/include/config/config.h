#pragma once

#include <stdbool.h>
#include <stdint.h>


bool config_get(const char* name, uintmax_t* out_value);
