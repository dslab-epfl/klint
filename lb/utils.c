#include "utils.h"

int expire_items_single_map(struct os_pool *chain,
                            void **vector,
                            struct os_map *map,
                            time_t time)
{
    int count = 0;
    size_t index = -1;
    while (os_pool_expire(chain, time, &index))
    {
        void *key = vector[index];
        os_map_remove(map, key);
        ++count;
    }
    return count;
}

unsigned lb_flow_hash(struct lb_flow* obj)
{
    // We don't really care what's in there
    return obj->src_ip;
}
