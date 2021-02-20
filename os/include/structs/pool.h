#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "os/clock.h"

//@ #include "proof/ghost_map.gh"


struct os_pool;

//@ predicate poolp(struct os_pool* pool, size_t size, time_t expiration_time, list<pair<size_t, time_t> > used_items);
//@ fixpoint bool pool_young(time_t time, time_t expiration_time, size_t k, time_t v) { return time < expiration_time || time - expiration_time <= v; }

struct os_pool* os_pool_alloc(size_t size, time_t expiration_time);
/*@ requires emp; @*/
/*@ ensures poolp(result, size, expiration_time, nil); @*/

bool os_pool_borrow(struct os_pool* pool, time_t time, size_t* out_index, bool* out_used);
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
             time != TIME_MAX &*&
             *out_index |-> _ &*&
             *out_used |-> _; @*/
/*@ ensures *out_index |-> ?index &*&
            *out_used |-> ?used &*&
            length(items) == size && ghostmap_forall(items, (pool_young)(time, exp_time)) ?
            	  (result == false &*&
            	   poolp(pool, size, exp_time, items))
            	: (result == true &*&
            	   poolp(pool, size, exp_time, ghostmap_set(items, index, time)) &*&
            	   index < size &*&
                   switch (ghostmap_get(items, index)) {
                   	case some(old): return used == true &*& old < time - exp_time;
                   	case none: return used == false;
                   }); @*/

void os_pool_refresh(struct os_pool* pool, time_t time, size_t index);
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
             time != TIME_MAX &*&
             index < size &*&
             ghostmap_get(items, index) != none; @*/
/*@ ensures poolp(pool, size, exp_time, ghostmap_set(items, index, time)); @*/

bool os_pool_used(struct os_pool* pool, size_t index, time_t* out_time);
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
             *out_time |-> _; @*/
/*@ ensures poolp(pool, size, exp_time, items) &*&
            switch (ghostmap_get(items, index)) {
              case none: return result == false &*& *out_time |-> _;
              case some(t): return result == true &*& *out_time |-> t;
            }; @*/

void os_pool_return(struct os_pool* pool, size_t index);
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
             index < size &*&
             ghostmap_get(items, index) != none; @*/
/*@ ensures poolp(pool, size, exp_time, ghostmap_remove(items, index)); @*/
