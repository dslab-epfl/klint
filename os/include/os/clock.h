#pragma once

#include <stdint.h>

typedef int64_t time_t;

time_t os_clock_time(void);


// Proof API
//@ #define malloc_block_times malloc_block_llongs
//@ #define PRED_times llongs