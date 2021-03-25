#pragma once

#include <stddef.h>


typedef void foreach_index_forever_function(size_t index, void* state);
_Noreturn void foreach_index_forever(size_t length, foreach_index_forever_function* func, void* state);
