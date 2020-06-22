#ifndef MAP_H_INCLUDED
#define MAP_H_INCLUDED

#include <stdbool.h>
#include <stdint.h>

//@ #include "proof/stdex.gh"

struct os_map;

//@ inductive map_item = map_item(void* key_addr, list<char> key, uint64_t value);
//@ fixpoint list<char> map_item_key(map_item item) { switch(item) { case map_item(key_addr, key, value): return key; } }
//@ predicate mapp(struct os_map* map, uint64_t key_size, uint64_t capacity, list<map_item> items);

/*@ fixpoint option<map_item> map_item_keyed(list<char> key, list<map_item> items) {
      switch(items) {
        case nil: return none;
        case cons(h, t): return map_item_key(h) == key ? some(h) : map_item_keyed(key, t);
      }
    } @*/

struct os_map* os_map_init(uint64_t key_size, uint64_t capacity);
/*@ requires 0 < capacity &*&
             0 < key_size; @*/
/*@ ensures result == 0 ? true : mapp(result, key_size, capacity, nil); @*/

bool os_map_get(struct os_map* map, void* key_ptr, uint64_t* value_out);
/*@ requires mapp(map, ?key_size, ?capacity, ?items) &*&
             chars(key_ptr, key_size, ?key) &*&
             *value_out |-> _; @*/
/*@ ensures mapp(map, key_size, capacity, items) &*&
            chars(key_ptr, key_size, key) &*&
            *value_out |-> ?value &*&
            switch(map_item_keyed(key, items)) {
              case none: return result == false;
              case some(it): return result == true &*& it == map_item(_, key, value);
            }; @*/

void os_map_put(struct os_map* map, void* key_ptr, uint64_t value);
/*@ requires mapp(map, ?key_size, ?capacity, ?items) &*&
             [0.25]chars(key_ptr, key_size, ?key) &*&
             length(items) < capacity &*&
             map_item_keyed(key, items) == none; @*/
/*@ ensures mapp(map, key_size, capacity, ?new_items) &*&
            length(new_items) == length(items) + 1 &*&
            true == subset(items, new_items) &*&
            map_item_keyed(key, new_items) == some(map_item(key_ptr, key, value)); @*/

void os_map_erase(struct os_map* map, void* key_ptr);
/*@ requires mapp(map, ?key_size, ?capacity, ?items) &*&
             [?frac]chars(key_ptr, key_size, ?key) &*&
             frac != 0.0 &*&
             map_item_keyed(key, items) == some(map_item(key_ptr, key, _)); @*/
/*@ ensures mapp(map, key_size, capacity, ?new_items) &*&
            length(new_items) == length(items) - 1 &*&
            true == subset(new_items, items) &*&
            map_item_keyed(key, new_items) == none &*&
            [frac + 0.25]chars(key_ptr, key_size, key); @*/

#endif
