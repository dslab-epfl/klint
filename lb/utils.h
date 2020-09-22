#ifndef _UTILS_H_INCLUDED_
#define _UTILS_H_INCLUDED_

#include "structs.h"
#include "os/structs/map.h"
#include "os/structs/pool.h"

int expire_items_single_map(struct os_pool *chain,
                            void **vector,
                            struct os_map *map,
                            time_t time);

unsigned lb_flow_hash(struct lb_flow* obj);

#endif //_UTILS_H_INCLUDED_
