#include "verif/functions.h"


__attribute__((noinline))
void foreach_index(size_t length, foreach_index_function* func, void* state)
{
	for (size_t index = 0; index < length; index++) {
		func(index, state);
	}
}

__attribute__((noinline))
void foreach_index_forever(size_t length, size_t batch_hint, foreach_index_forever_function* func, void* state)
{
	size_t index = 0;
	while (true) {
		for (size_t batch = 0; batch < batch_hint; batch++) {
			if (!func(index, state)) {
				break;
			}
		}

		index = index + 1;
		if (index == length) {
			index = 0;
		}
	}
}

__attribute__((noinline))
void foreach_index_set(size_t length, size_t* array, size_t value)
{
	for (size_t index = 0; index < length; index++) {
		array[index] = value;
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
