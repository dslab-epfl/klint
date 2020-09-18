#ifndef _CHT_H_INCLUDED_
#define _CHT_H_INCLUDED_

#include <stdint.h>
#include "os/structs/pool.h"

#define MAX_CHT_HEIGHT 40000

struct cht
{
    int *data;
    uint32_t height;
    uint32_t backend_capacity;
};

struct cht *cht_alloc(uint32_t cht_height, uint32_t backend_capacity);

int cht_find_preferred_available_backend(struct cht *cht, uint64_t hash, struct os_pool *active_backends, int *chosen_backend);

#endif //_CHT_H_INCLUDED_
