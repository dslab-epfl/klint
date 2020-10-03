#include "cht.h"

#include "os/memory.h"

static uint64_t loop(uint64_t k, uint64_t capacity)
{
    return k % capacity;
}

struct cht *cht_alloc(uint32_t cht_height, uint32_t backend_capacity)
{
    // Create CHT
    struct cht *cht = os_memory_alloc(1, sizeof(struct cht));
    cht->height = cht_height;
    cht->backend_capacity = backend_capacity;
    cht->data = os_memory_alloc((size_t)(cht_height * backend_capacity), sizeof(uint32_t));

    // Create permutations
    uint32_t *permutations = os_memory_alloc((size_t)(cht_height * backend_capacity), sizeof(uint32_t));
    for (uint32_t i = 0; i < backend_capacity; ++i)
    {
        uint64_t offset = loop(i * 31, cht_height);
        uint64_t shift = loop(i, cht_height - 1) + 1;
        for (uint64_t j = 0; j < cht_height; ++j)
        {
            uint64_t permut = loop(offset + shift * j, cht_height);
            permutations[i * cht_height + j] = (uint32_t)permut;
        }
    }

    // Fill the CHT
    uint32_t *next = os_memory_alloc((size_t)(cht_height), sizeof(uint32_t));
    for (uint32_t i = 0; i < cht_height; ++i)
    {
        for (uint32_t j = 0; j < backend_capacity; ++j)
        {
            uint32_t bucket_id = permutations[j * cht_height + i];
            uint32_t priority = next[bucket_id];
            next[bucket_id] += 1;
            cht->data[(size_t)(backend_capacity * bucket_id + priority)] = j;
        }
    }

    // free(next);
    // free(permutations);
    return cht;
}

uint32_t cht_find_preferred_available_backend(struct cht *cht, uint64_t hash, struct os_pool *active_backends, uint32_t *chosen_backend)
{
    uint64_t cht_bucket = loop(hash, cht->height) * cht->backend_capacity;
    for (uint32_t i = 0; i < cht->backend_capacity; ++i)
    {
        uint32_t candidate = cht->data[cht_bucket + i];
        time_t out_time;
        if (os_pool_used(active_backends, (size_t)candidate, &out_time))
        {
            *chosen_backend = candidate;
            return 1;
        }
    }
    return 0;
}

void angr_breakpoint() {
    print("Debug");
}