#include "verif/functions.h"

#include <stdbool.h>

//#include "os/memory.h"


/*void** ptrarray_map(size_t items_count, void** items, map_function* mapper)
{
	void** result = os_memory_alloc(items_count, sizeof(void*));
	for (size_t n = 0; n < items_count; n++) {
		result[n] = mapper(items[n], n);
	}
	return result;
}
*/

__attribute__((noinline))
void foreach_index(size_t length, foreach_index_function* func, void* state)
{
	for (size_t index = 0; index < length; index++) {
		func(index, state);
	}
}

__attribute__((noinline))
void foreach_index_forever(size_t length, foreach_index_function* func, void* state)
{
	size_t index = 0;
	while (true) {
		func(index, state);

		index = index + 1;
		if (index == length) {
			index = 0;
		}
	}
}

__attribute__((noinline))
uint32_t argmin_uint32(size_t length, argmin_uint32_function* func, void* state)
{
	uint32_t min = (uint32_t) -1;
	uint32_t argmin = (uint32_t) -1;
	for (size_t index = 0; index < length; index++) {
		uint32_t arg;
		uint32_t candidate = func(index, state, &arg);
		if (candidate <= min) {
			min = candidate;
			argmin = arg;
		}
	}
	return argmin;
}
