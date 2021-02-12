#pragma once

#include <stddef.h>
#include <stdint.h> // for SIZE_MAX


struct buffer_pool;


struct buffer_pool* buffer_pool_create(size_t count, size_t size);
// ensures buffer_poolp(?map, size) &*& length(map) == count;

bool buffer_pool_take(struct buffer_pool* pool, size_t count, void** out_buffers);
// requires buffer_poolp(?map, ?element_size) &*& bufps(out_buffers, count, ...);
// ensures size >= count ? result == true &*& bufs(out_buffers, count, size, ...???bufs???) &*& buffer_poolp(map_remove_bulk(map, bufs), size - count)
//                       : result == false &*& buffer_poolp(map, size);

bool buffer_pool_put(struct buffer_pool* pool, size_t count, void** buffers);
// requires buffer_poolp(?map, ?element_size) &*& bufs(buffers, count, size, ...?how to do this?...);
// ensures buffer_poolp(?new_map, ?element_size) &*&
//         length(map) + count <= SIZE_MAX ? result == true &*& new_map == add_multiple???(map, bufs) &*& new_size == size + count
//                                          : result == false &*& bufs(...) &*& new_map == map &*& new_size == size;
// ... probably easier to put buffer_poolp inside the ?:
