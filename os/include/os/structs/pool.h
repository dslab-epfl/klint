#pragma once

#include <stdbool.h>
#include <stddef.h>
#include "os/clock.h"

//@ #include "proof/ghost_map.gh"

struct os_pool;

//@ predicate poolp(struct os_pool* pool, size_t size, list<pair<size_t, time_t> > items);

//@ fixpoint bool pool_upperbounded(time_t bound, size_t k, time_t v) { return v <= bound; }
//@ fixpoint bool pool_lowerbounded(time_t bound, size_t k, time_t v) { return v > bound; }

struct os_pool* os_pool_alloc(size_t size);
/*@ requires size <= (SIZE_MAX / 16) - 2; @*/
/*@ ensures poolp(result, size, nil); @*/

bool os_pool_borrow(struct os_pool* pool, time_t time, size_t* out_index);
/*@ requires poolp(pool, ?size, ?items) &*&
             true == ghostmap_forall(items, (pool_upperbounded)(time)) &*&
             *out_index |-> _; @*/
/*@ ensures *out_index |-> ?index &*&
            index < size &*&
            length(items) == size ? (result == false &*&
                                     poolp(pool, size, items))
                                  : (result == true &*&
                                     ghostmap_get(items, index) == none &*&
                                     poolp(pool, size, ghostmap_set(items, index, time))); @*/

void os_pool_return(struct os_pool* pool, size_t index);
/*@ requires poolp(pool, ?size, ?items) &*&
             index < size &*&
             ghostmap_get(items, index) != none; @*/
/*@ ensures poolp(pool, size, ghostmap_remove(items, index)); @*/

void os_pool_refresh(struct os_pool* pool, time_t time, size_t index);
/*@ requires poolp(pool, ?size, ?items) &*&
             true == ghostmap_forall(items, (pool_upperbounded)(time)) &*&
             index < size &*&
             ghostmap_get(items, index) != none; @*/
/*@ ensures poolp(pool, size, ghostmap_set(items, index, time)); @*/

bool os_pool_used(struct os_pool* pool, size_t index, time_t* out_time);
/*@ requires poolp(pool, ?size, ?items) &*&
             index < size &*&
             *out_time |-> _; @*/
             /*@ ensures poolp(pool, size, items) &*&
                         switch (ghostmap_get(items, index)) {
                           case none: return result == false &*& *out_time |-> _;
                           case some(t): return result == true &*& *out_time |-> t;
                         }; @*/

bool os_pool_expire(struct os_pool* pool, time_t time, size_t* out_index);
/*@ requires poolp(pool, ?size, ?items) &*&
             *out_index |-> _; @*/
/*@ ensures *out_index |-> ?index &*&
            index < size &*&
            ghostmap_forall(items, (pool_lowerbounded)(time)) ? (result == false &*&
                                                                 poolp(pool, size, items))
                                                              : (result == true &*&
                                                                 ghostmap_get(items, index) == some(?old) &*&
                                                                 old < time &*&
                                                                 poolp(pool, size, ghostmap_remove(items, index))); @*/
