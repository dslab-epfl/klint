#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "os/clock.h"

//@ #include "proof/ghost_map.gh"

// TODO move
typedef uint64_t time_t;
#define TIME_INVALID ((time_t) 0xFFFFFFFFFFFFFFFFull)
//#define malloc_block_times malloc_block_ullongs
#define PRED_times ullongs
#define chars_to_times chars_to_ullongs
//@ predicate PRED_time(time_t* p; time_t t) = integer_(p, sizeof(time_t), false, t);
//@ lemma_auto void chars_to_time(void *p); requires [?f]chars(p, sizeof(time_t), ?cs); ensures [f]integer_(p, sizeof(time_t), false, _);


struct os_pool;

//@ predicate poolp(struct os_pool* pool, size_t size, time_t expiration_time, list<pair<size_t, time_t> > used_items);
//@ fixpoint bool pool_lowerbounded(time_t bound, size_t k, time_t v) { return v > bound; }

struct os_pool* os_pool_alloc(size_t size, time_t expiration_time);
/*@ requires emp; @*/
/*@ ensures poolp(result, size, expiration_time, nil); @*/

bool os_pool_borrow(struct os_pool* pool, time_t time, size_t* out_index, bool* out_used);
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
             *out_index |-> _ &*&
             *out_used |-> _; @*/
/*@ ensures length(items) == size &*& ghostmap_forall(items, (pool_lowerbounded)(time)) ?
            	  (result == false &*&
            	   poolp(pool, size, exp_time, items))
            	: (result == true &*&
            	   *out_index |-> ?index &*&
            	   *out_used |-> ?used &*&
            	   poolp(pool, size, exp_time, ghostmap_set(items, index, time)) &*&
            	   index < size &*&
            	   used ? (ghostmap_get(items, index) == some(?old) &*& old < time - exp_time)
            	        : (ghostmap_get(items, index) == none)); @*/

void os_pool_refresh(struct os_pool* pool, time_t time, size_t index);
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
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
