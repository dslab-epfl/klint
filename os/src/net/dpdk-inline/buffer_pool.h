#pragma once

#include <stdbool.h>
#include <stddef.h>


struct buffer_pool;


struct buffer_pool* buffer_pool_create(size_t capacity, size_t buffer_size);
// ensures buffer_poolp(empty_map, capacity, buffer_size);

bool buffer_pool_take(struct buffer_pool* pool, size_t count, void** out_buffers);
// requires buffer_poolp(?map, ?capacity, ?element_size) &*& bufps(out_buffers, count, ...);
// ensures size >= count ? result == true &*& bufs(out_buffers, count, element_size, ...???bufs???) &*& buffer_poolp(map_remove_bulk(map, bufs), capacity, element_size)
//                       : result == false &*& buffer_poolp(map, capacity, element_size);

bool buffer_pool_put(struct buffer_pool* pool, size_t count, void** buffers);
// requires buffer_poolp(?map, ?capacity, ?element_size) &*& bufs(buffers, count, size, ...?how to do this?...);
// ensures buffer_poolp(?new_map, capacity, element_size) &*&
//         length(map) + count <= capacity ? result == true &*& new_map == add_multiple???(map, bufs)
//                                         : result == false &*& bufs(...) &*& new_map == map;
// ... probably easier to put buffer_poolp inside the ?:
