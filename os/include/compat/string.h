#pragma once

#include <stddef.h>

// simple versions, maybe the compiler will be smart enough to improve them

#define memcpy(dst, src, size) for(size_t x_ = 0; x_ < size; x_++) { *(((uint8_t*)dst) + x_) = *(((uint8_t*)src) + x_); }

#define memset(s, c, n) for(size_t x_ = 0; x_ < n; x_++) { *(((uint8_t*) s) + x_) = c; }
