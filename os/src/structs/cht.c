#include "structs/cht.h"

#include "os/memory.h"

static size_t loop(size_t k, size_t capacity)
{
    return k % capacity;
}

struct cht *cht_alloc(size_t cht_height, size_t backend_capacity)
{
    // Create CHT
    struct cht *cht = os_memory_alloc(1, sizeof(struct cht));
    cht->height = cht_height;
    cht->backend_capacity = backend_capacity;
    cht->data = os_memory_alloc((size_t)(cht_height * backend_capacity), sizeof(size_t));

    // Create permutations
    size_t *permutations = os_memory_alloc((size_t)(cht_height * backend_capacity), sizeof(size_t));
    for (size_t i = 0; i < backend_capacity; ++i)
    {
        size_t offset = loop(i * 31, cht_height);
        size_t shift = loop(i, cht_height - 1) + 1;
        for (size_t j = 0; j < cht_height; ++j)
        {
            size_t permut = loop(offset + shift * j, cht_height);
            permutations[i * cht_height + j] = (size_t)permut;
        }
    }

    // Fill the CHT
    size_t *next = os_memory_alloc((size_t)(cht_height), sizeof(size_t));
    for (size_t i = 0; i < cht_height; ++i)
    {
        for (size_t j = 0; j < backend_capacity; ++j)
        {
            size_t bucket_id = permutations[j * cht_height + i];
            size_t priority = next[bucket_id];
            next[bucket_id] += 1;
            cht->data[(size_t)(backend_capacity * bucket_id + priority)] = j;
        }
    }

    // free(next);
    // free(permutations);
    return cht;
}

bool cht_find_preferred_available_backend(struct cht *cht, void* obj, size_t obj_size, struct index_pool *active_backends, size_t *chosen_backend, time_t time)
{
    size_t cht_bucket = loop(os_memory_hash(obj, obj_size), cht->height) * cht->backend_capacity;
    for (size_t i = 0; i < cht->backend_capacity; ++i)
    {
        size_t candidate = cht->data[cht_bucket + i];
        if (index_pool_used(active_backends, time, candidate))
        {
            *chosen_backend = candidate;
            return true;
        }
    }
    return false;
}
