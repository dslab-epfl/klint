#include "verif/functions.h"


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
