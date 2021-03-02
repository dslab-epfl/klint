#pragma once

#include <stddef.h>
#include <stdint.h>


//typedef void* map_function(void* item, size_t index);
//void** ptrarray_map(size_t items_count, void** items, map_function* mapper);

typedef void foreach_index_function(size_t index, void* state);
void foreach_index(size_t length, foreach_index_function* func, void* state);
_Noreturn void foreach_index_forever(size_t length, foreach_index_function* func, void* state);

typedef uint32_t argmin_uint32_function(size_t index, void* state, uint32_t* out_arg);
uint32_t argmin_uint32(size_t length, argmin_uint32_function* func, void* state);
