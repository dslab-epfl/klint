#include "verif/functions.h"

#include <stdbool.h>


void foreach_index_forever(size_t length, foreach_index_forever_function* func, void* state)
{
	while (true) {
		for (size_t index = 0; index < length; index++) {
			func(index, state);
		}
	}
}
