#ifndef OS_CLOCK_H
#define OS_CLOCK_H

#include <stdint.h>

typedef int64_t time_t;

time_t os_clock_time(void);


// Proof API
#define malloc_block_times malloc_block_llongs
#define PRED_times llongs
#define chars_to_times chars_to_llongs

#endif