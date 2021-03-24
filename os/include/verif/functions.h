#pragma once

#include <stdbool.h>
#include <stddef.h>


// The batch hint is optional but helps with latency
typedef bool foreach_index_forever_function(size_t index, void* state);
_Noreturn void foreach_index_forever(size_t length, size_t batch_hint, foreach_index_forever_function* func, void* state);
