#ifndef DCHAIN_H_INCLUDED
#define DCHAIN_H_INCLUDED

#include <stdbool.h>
#include <stdint.h>

//@ #include "proof/stdex.gh"

// Configurable time_t
#define malloc_block_times malloc_block_llongs
#define time_integer llong_integer
#define times llongs
#define time_t int64_t

struct os_dchain;

//@ predicate dchainp(struct os_dchain* dchain, uint64_t index_range, list<pair<uint64_t, time_t> > items);

// TODO unify map and dchain 'list' abstractions into operations on list<pair<k, v> >
//      (and always put the 'items' in either first or last, but be consistent...)
/*@ fixpoint option<time_t> dchain_items_keyed(int key, list<pair<uint64_t, time_t> > items) {
      switch(items) {
        case nil: return none;
        case cons(h, t): return fst(h) == key ? some(snd(h)) : dchain_items_keyed(key, t);
      }
    } @*/
/*@ fixpoint list<pair<uint64_t, time_t> > dchain_items_update(int key, time_t value, list<pair<uint64_t, time_t> > items) {
      switch(items) {
        case nil: return nil;
        case cons(h, t): return fst(h) == key ? cons(pair(key, value), t) : cons(h, dchain_items_update(key, value, t));
      }
    } @*/
/*@ fixpoint list<pair<uint64_t, time_t> > dchain_items_remove(int key, list<pair<uint64_t, time_t> > items) {
      switch(items) {
        case nil: return nil;
        case cons(h, t): return fst(h) == key ? t : cons(h, dchain_items_remove(key, t));
      }
    } @*/
/*@ fixpoint bool dchain_items_lowerbounded(list<pair<uint64_t, time_t> > items, time_t bound) {
      switch(items) {
        case nil: return true;
        case cons(h, t):
          return switch(h) {
            case pair(fst, snd): return snd >= bound && dchain_items_upperbounded(t, bound);
          };
      } @*/
/*@ fixpoint bool dchain_items_upperbounded(list<pair<uint64_t, time_t> > items, time_t bound) {
      switch(items) {
        case nil: return true;
        case cons(h, t):
          return switch(h) {
            case pair(fst, snd): return snd <= bound && dchain_items_upperbounded(t, bound);
          };
      } @*/

struct os_dchain* os_dchain_init(uint64_t index_range);
/*@ requires 0 < index_range; @*/
/*@ ensures result == 0 ? true : dchainp(result, index_range, nil); @*/

bool os_dchain_add(struct os_dchain* dchain, time_t time, uint64_t* index_out);
/*@ requires dchainp(dchain, ?index_range, ?items) &*&
             true == dchain_items_upperbounded(items, time) &*&
             *index_out |-> _; @*/
/*@ ensures *index_out |-> ?index &*&
            0 <= index &*& index < index_range &*&
            length(items) == index_range ? (result == false &*&
                                            dchainp(dchain, index_range, items))
                                         : (result == true &*&
                                            dchain_items_keyed(index, items) == none &*&
                                            dchainp(dchain, index_range, ?new_items) &*&
                                            true == subset(items, new_items) &*&
                                            length(new_items) == length(items) + 1 &*&
                                            dchain_items_keyed(index, new_items) == some(time)); @*/

void os_dchain_refresh(struct os_dchain* dchain, time_t time, uint64_t index);
/*@ requires dchainp(dchain, ?index_range, ?items) &*&
             true == dchain_items_upperbounded(items, time) &*&
             0 <= index &*& index < index_range &*&
             dchain_items_keyed(index, items) != none; @*/
/*@ ensures dchainp(dchain, index_range, ?new_items) &*&
            new_items == dchain_items_update(index, time, items); @*/

bool os_dchain_expire(struct os_dchain* dchain, time_t time, uint64_t* index_out);
/*@ requires dchainp(dchain, ?index_range, ?items) &*&
             *index_out |-> _; @*/
/*@ ensures *index_out |-> ?index &*&
            0 <= index &*& index < index_range &*&
            dchain_items_lowerbounded(items, time) ? (result == false &*&
                                                      dchainp(dchain, index_range, items))
                                                   : (result == true &*&
                                                      dchain_items_keyed(index, items) == some(?old) &*&
                                                      old < time &*&
                                                      dchainp(dchain, index_range, ?new_items) &*&
                                                      new_time_opts == dchain_items_remove(index, items)); @*/

bool os_dchain_get(struct os_dchain* dchain, uint64_t index, time_t* time_out);
/*@ requires dchainp(dchain, ?index_range, ?items) &*&
             0 <= index &*& index < index_range &*&
             *time_out |-> _; @*/
/*@ ensures dchainp(dchain, index_range, items) &*&
            switch (dchain_items_keyed(index, items)) {
              case none: return result == false &*& *time_out |-> _;
              case some(t): return result == true &*& *time_out |-> t;
            }; @*/

// only used in load balancer
//void os_dchain_remove(struct os_dchain* dchain, int index);
///*@ requires dchainp(dchain, ?index_range, ?items) &*&
//             0 <= index &*& index < index_range &*&
//             dchain_items_keyed(index, items) != none; @*/
///*@ ensures dchainp(dchain, index_range, ?new_items) &*&
//            new_items == dchain_items_remove(index, items); @*/

#endif
