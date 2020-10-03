#ifndef _CHT_H_INCLUDED_
#define _CHT_H_INCLUDED_

#include <stdint.h>
#include "os/structs/pool.h"

//@ #include "os/include/proof/ghost_map.gh"

#define MAX_CHT_HEIGHT 40000

struct cht
{
    uint32_t *data;
    uint32_t height;
    uint32_t backend_capacity;
};

// @TODO: how to check that cht_height is prime ?

/*@ 
    predicate chtp(struct cht* cht);

    fixpoint bool is_not_available(uint32_t backend_capacity, size_t index, time_t time) {
        return index < 0 || index >= backend_capacity;
    }
@*/

struct cht *cht_alloc(uint32_t cht_height, uint32_t backend_capacity);
/*@ requires
        0 < cht_height &*& cht_height < MAX_CHT_HEIGHT &*&
        0 < backend_capacity &*& backend_capacity < cht_height &*&
        cht_height * backend_capacity < SIZE_MAX
@*/
/*@ ensures
        chtp(result)
@*/

uint32_t cht_find_preferred_available_backend(struct cht *cht, uint64_t hash, struct os_pool *active_backends, uint32_t *chosen_backend);
/*@ requires
        chtp(cht) &*&
        poolp(active_backends, ?size, ?backends) &*& cht->backend_capacity <= size &*&
        *chosen_backend |-> _;
@*/
/*@ ensures
        chtp(cht) &*& poolp(active_backends, size, backends) &*&
        ghostmap_forall(active_backends, is_not_available(cht->backend_capacity))  
            ?   result == 0
            :   (*chosen_backend |-> ?index &*& 0 <= index &*& index < cht->backend_capacity &*&
                ghostmap_get(backends, index) == some(?t)) &*& result == 1;

@*/

void angr_breakpoint();

#endif //_CHT_H_INCLUDED_
