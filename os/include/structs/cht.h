#pragma once

#include <stdint.h>
#include "os/structs/pool.h"

//@ #include "proof/ghost_map.gh"

#define MAX_CHT_HEIGHT 40000

struct cht
{
    size_t *data;
    size_t height;
    size_t backend_capacity;
};

// @TODO: how to check that cht_height is prime ?

/*@ 
    predicate chtp(struct cht* cht);

    fixpoint bool is_not_available(uint32_t backend_capacity, size_t index, time_t time) {
        return index < 0 || index >= backend_capacity;
    }
@*/

struct cht *cht_alloc(size_t cht_height, size_t backend_capacity);
/*@ requires
        0 < cht_height &*& cht_height < MAX_CHT_HEIGHT &*&
        0 < backend_capacity &*& backend_capacity < cht_height &*&
        cht_height * backend_capacity < SIZE_MAX; @*/
/*@ ensures
        chtp(result); @*/

bool cht_find_preferred_available_backend(struct cht *cht, void* obj, size_t obj_size, struct os_pool *active_backends, size_t *chosen_backend);
/*@ requires
        chtp(cht) &*&
        poolp(active_backends, ?size, ?backends) &*& cht->backend_capacity <= size &*&
        *chosen_backend |-> _;
@*/
/*@ ensures
        chtp(cht) &*& poolp(active_backends, size, backends) &*&
        ghostmap_forall(backends, (is_not_available)(cht->backend_capacity))  
            ?   result == false
            :   (*chosen_backend |-> ?index &*& 0 <= index &*& index < cht->backend_capacity &*&
                ghostmap_get(backends, index) == some(?t)) &*& result == true;

@*/
