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
    cht->data = os_memory_alloc((size_t)(cht_height * backend_capacity), sizeof(int));

    // Create permutations
    int *permutations = os_memory_alloc((size_t)(cht_height * backend_capacity), sizeof(int));
    for (uint32_t i = 0; i < backend_capacity; ++i)
    {
        uint32_t offset_absolut = i * 31;
        uint64_t offset = loop(offset_absolut, cht_height);
        uint64_t base_shift = loop(i, cht_height - 1);
        uint64_t shift = base_shift + 1;
        for (uint32_t j = 0; j < cht_height; ++j)
        {
            uint64_t permut = loop(offset + shift * j, cht_height);
            permutations[i * cht_height + j] = (int)permut;
        }
    }

    // Fill the CHT
    int *next = os_memory_alloc((size_t)(cht_height), sizeof(int));
    for (uint32_t i = 0; i < cht_height; ++i)
    {
        for (uint32_t j = 0; j < backend_capacity; ++j)
        {
            uint32_t *value;
            uint32_t index = j * cht_height + i;
            int bucket_id = permutations[index];
            int priority = next[bucket_id];
            next[bucket_id] += 1;
            cht->data[(size_t)(backend_capacity * ((uint32_t)bucket_id) + ((uint32_t)priority))] = j;
        }
    }

    free(next);
    free(permutations);
    return cht;
}

int cht_find_preferred_available_backend(struct cht *cht, uint64_t hash, struct os_pool *active_backends, int *chosen_backend)
{
    uint64_t start = loop(hash, cht->height);
    uint64_t cht_bucket = start * cht->backend_capacity;
    for (uint32_t i = 0; i < cht->backend_capacity; ++i)
    {
        uint64_t candidate_idx = cht_bucket + i;
        int candidate = cht->data[candidate_idx];
        time_t out_time;
        if (os_pool_used(active_backends, (size_t) candidate, out_time))
        {
            *chosen_backend = candidate;
            return 1;
        }
    }
    return 0;
}
