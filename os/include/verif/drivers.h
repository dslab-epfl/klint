#pragma once

#include <stddef.h>
#include <stdint.h>


uint64_t* descriptor_ring_alloc(size_t count);


typedef void foreach_index_forever_function(size_t index, void* state);
_Noreturn void foreach_index_forever(size_t length, foreach_index_forever_function* func, void* state);
