#pragma once

#include <stdint.h>

#include "structs/index_pool.h"

//@ #include "proof/ghost_map.gh"

#define MAX_CHT_HEIGHT 40000

struct cht
{
    device_t *data;
    device_t height;
    device_t backend_capacity;
    uint8_t _padding[4];
};

// @TODO: how to check that cht_height is prime ?

/*@ 
    predicate chtp(struct cht* cht);

    fixpoint bool is_not_available(uint32_t backend_capacity, size_t index, time_t time) {
        return index < 0 || index >= backend_capacity;
    }
@*/

struct cht *cht_alloc(device_t cht_height, device_t backend_capacity);
/*@ requires
        0 < cht_height &*& cht_height < MAX_CHT_HEIGHT &*&
        0 < backend_capacity &*& backend_capacity < cht_height; @*/
/*@ ensures
        chtp(result); @*/

bool cht_find_preferred_available_backend(struct cht *cht, void* obj, size_t obj_size, struct index_pool *active_backends, device_t* chosen_backend, time_t time);
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
