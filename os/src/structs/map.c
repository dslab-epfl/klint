#include "os/structs/map.h"

// !!! IMPORTANT !!! to verify, 'default_value_eq_zero' needs to be turned from a lemma_auto to a lemma in prelude_core.gh, see verifast issue 68

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include "proof/generic_ops.h"

//@ #include "proof/chain-buckets.gh"
//@ #include "proof/listexex.gh"
//@ #include "proof/mod-pow2.gh"
//@ #include "proof/modulo.gh"
//@ #include "proof/nth-prop.gh"
//@ #include "proof/stdex.gh"

struct os_map {
  char** kaddrs;
  char* busybits; // TODO: change to bool once VeriFast handles sizeof(bool), malloc/free with bools, etc.
  uint32_t* hashes;
  uint32_t* chains;
  uint64_t* values;
  size_t capacity;
  size_t key_size;
};

/*@
  fixpoint int opts_size<kt>(list<option<kt> > opts) {
    switch(opts) {
      case nil: return 0;
      case cons(h,t): return (h == none ? 0 : 1) + opts_size(t);
    }
  }

  // Addresses + busybits => key options
  predicate key_opt_list(size_t key_size, list<char*> kaddrs, list<char> busybits;
                         list<option<list<char> > > key_opts) =
    switch(busybits) {
      case nil:
        return kaddrs == nil &*& key_opts == nil;
      case cons(bbh, bbt):
        return kaddrs == cons(?kaddrsh, ?kaddrst) &*&
               key_opt_list(key_size, kaddrst, bbt, ?key_optst) &*&
               bbh != 0 ? ([0.25]chars(kaddrsh, key_size, ?key_optsh) &*& key_opts == cons(some(key_optsh), key_optst)) : (key_opts == cons(none, key_optst));
    };

  // Key options => hashes
  // NOTE: It's important that we say nothing about hashes of none keys, which is why this can't return a list<unsigned> (which would need to reason about this info)
  fixpoint bool hash_list(list<option<list<char> > > key_opts, list<uint32_t> hashes) {
    switch(key_opts) {
      case nil:
        return hashes == nil;
      case cons(h,t):
        return hashes != nil &&
               hash_list(t, tail(hashes)) &&
               (h == none || head(hashes) == hash_fp(get_some(h)));
    }
  }

  fixpoint bool has_given_hash(int pos, size_t capacity, pair<list<char>, nat> chain) {
    return pos == loop_fp(hash_fp(fst(chain)), capacity);
  }

  fixpoint bool key_chains_start_on_hash_fp(list<bucket<list<char> > > buckets, int pos, size_t capacity) {
    switch(buckets) {
      case nil: return true;
      case cons(h,t):
        return switch(h) { case bucket(chains):
            return forall(chains, (has_given_hash)(pos, capacity)) &&
                   key_chains_start_on_hash_fp(t, pos + 1, capacity);
          };
    }
  }

  // Chains + buckets => key options
  predicate buckets_keys_insync(size_t capacity, list<uint32_t> chains, list<bucket<list<char> > > buckets;
                                list<option<list<char> > > key_opts) =
    chains == buckets_get_chns_fp(buckets) &*&
    true == buckets_ok(buckets) &*&
    true == key_chains_start_on_hash_fp(buckets, 0, capacity) &*&
    key_opts == buckets_get_keys_fp(buckets) &*&
    length(buckets) == capacity;

  // Partial: Chains + buckets => key options
  predicate buckets_keys_insync_Xchain(size_t capacity, list<uint32_t> chains, list<bucket<list<char> > > buckets, int start, int fin; list<option<list<char> > > key_opts) =
    chains == add_partial_chain_fp(start,
                                   (fin < start) ? capacity + fin - start :
                                                   fin - start,
                                   buckets_get_chns_fp(buckets)) &*&
    true == buckets_ok(buckets) &*&
    true == key_chains_start_on_hash_fp(buckets, 0, capacity) &*&
    key_opts == buckets_get_keys_fp(buckets) &*&
    length(buckets) == capacity;

  // Addresses + key options + values => Map values + Map addresses
  // NOTE: It is crucial that this predicate be expressed without using ghostmap_set!
  //       Using set would impose an order, which makes the rest of the proof (probably?) infeasible.
  predicate map_valuesaddrs(list<char*> kaddrs, list<option<list<char> > > key_opts, list<uint64_t> values,
                            list<pair<list<char>, uint64_t> > map_values, list<pair<list<char>, char*> > map_addrs) =
    switch(kaddrs) {
      case nil:
        return key_opts == nil &*&
               values == nil &*&
               map_values == nil &*&
               map_addrs == nil;
      case cons(kaddrsh, kaddrst):
        return key_opts == cons(?key_optsh, ?key_optst) &*&
               values == cons(?valuesh, ?valuest) &*&
               map_valuesaddrs(kaddrst, key_optst, valuest, ?map_values_rest, ?map_addrs_rest) &*&
               length(map_values) == length(map_addrs) &*&
               true == ghostmap_distinct(map_values) &*&
               true == ghostmap_distinct(map_addrs) &*&
               (key_optsh == none ? (map_values == map_values_rest &*&
                                     map_addrs == map_addrs_rest)
                                  : (map_values_rest == ghostmap_remove(map_values, get_some(key_optsh)) &*&
                                     map_addrs_rest == ghostmap_remove(map_addrs, get_some(key_optsh)) &*&
                                     some(valuesh) == ghostmap_get(map_values, get_some(key_optsh)) &*&
                                     some(kaddrsh) == ghostmap_get(map_addrs, get_some(key_optsh)) ));
               
    };

  // Keys + busybits + hashes + values => key options + map values + map addresses
  predicate mapping_core(size_t key_size, size_t capacity,
                         char** kaddrs_ptr, char* busybits_ptr, uint32_t* hashes_ptr, uint64_t* values_ptr,
                         list<option<list<char> > > key_opts, list<pair<list<char>, uint64_t> > map_values, list<pair<list<char>, char*> > map_addrs) =
     kaddrs_ptr[0..capacity] |-> ?kaddrs &*&
     busybits_ptr[0..capacity] |-> ?busybits &*&
     hashes_ptr[0..capacity] |-> ?hashes &*&
     values_ptr[0..capacity] |-> ?values &*&
     key_opt_list(key_size, kaddrs, busybits, key_opts) &*&
     map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs) &*&
     true == hash_list(key_opts, hashes) &*&
     true == opt_no_dups(key_opts) &*&
     true == ghostmap_distinct(map_values) &*&
     true == ghostmap_distinct(map_addrs) &*&
     length(key_opts) == capacity &*&
     opts_size(key_opts) == length(map_values) &*&
     length(map_values) == length(map_addrs);
  
  // Core + "chains" performance optimization
  predicate mapping(size_t key_size, size_t capacity,
                    char** kaddrs_ptr, char* busybits_ptr, uint32_t* hashes_ptr, uint32_t* chains_ptr, uint64_t* values_ptr, list<bucket<list<char> > > buckets,
                    list<option<list<char> > > key_opts, list<pair<list<char>, uint64_t> > map_values, list<pair<list<char>, char*> > map_addrs) =
     mapping_core(key_size, capacity, kaddrs_ptr, busybits_ptr, hashes_ptr, values_ptr, key_opts, map_values, map_addrs) &*&
     chains_ptr[0..capacity] |-> ?chains &*&
     buckets_keys_insync(capacity, chains, buckets, key_opts);

  predicate mapp(struct os_map* map, size_t key_size, size_t capacity, list<pair<list<char>, uint64_t> > map_values, list<pair<list<char>, char*> > map_addrs) =
    malloc_block_os_map(map) &*&
    map->kaddrs |-> ?kaddrs_ptr &*&
    map->busybits |-> ?busybits_ptr &*&
    map->hashes |-> ?hashes_ptr &*&
    map->chains |-> ?chains_ptr &*&
    map->values |-> ?values_ptr &*&
    map->capacity |-> capacity &*&
    map->key_size |-> key_size &*&
    malloc_block_pointers(kaddrs_ptr, capacity) &*&
    malloc_block_chars(busybits_ptr, capacity) &*&
    malloc_block_uints(hashes_ptr, capacity) &*&
    malloc_block_uints(chains_ptr, capacity) &*&
    malloc_block_ullongs(values_ptr, capacity) &*&
    mapping(key_size, capacity, kaddrs_ptr, busybits_ptr, hashes_ptr, chains_ptr, values_ptr, _, _, map_values, map_addrs) &*&
    is_pow2(capacity, N63) != none;
@*/

static size_t loop(size_t pos, size_t capacity)
//@ requires 0 < capacity &*& is_pow2(capacity, N63) != none;
//@ ensures 0 <= result &*& result < capacity &*& result == loop_fp(pos, capacity);
{
  //@ nat m = is_pow2_some(capacity, N63);
  //@ mod_bitand_equiv(pos, capacity, m);
  //@ div_mod_gt_0(pos % capacity, pos, capacity);
  return pos & (capacity - 1);
}

/*@
lemma list<char> extract_key_at_index(list<char*> kaddrs_b, list<char> busybits_b, list<option<list<char> > > key_opts_b, int n, 
                                      list<char> busybits, list<option<list<char> > > key_opts)
  requires key_opt_list(?key_size, ?kaddrs, busybits, key_opts) &*&
           key_opt_list(key_size, kaddrs_b, busybits_b, key_opts_b) &*&
           0 <= n &*& n < length(busybits) &*& 0 != nth(n, busybits);
  ensures nth(n, key_opts) == some(result) &*& [0.25]chars(nth(n, kaddrs), key_size, result) &*&
          key_opt_list(key_size, drop(n+1, kaddrs), drop(n+1, busybits), drop(n+1, key_opts)) &*&
          key_opt_list(key_size,
                       append(reverse(take(n, kaddrs)), kaddrs_b),
                       append(reverse(take(n, busybits)), busybits_b),
                       append(reverse(take(n, key_opts)), key_opts_b));
{
  open key_opt_list(_, kaddrs, _, _);
  switch(busybits) {
    case nil:
      assert(length(busybits) == 0);
      return nil;
    case cons(bbh, bbt):
      switch(kaddrs) {
        case nil: return nil;
        case cons(kph, kpt):
          switch(key_opts) {
            case nil: return nil;
            case cons(kh, kt) :
            if (n == 0) {
              switch(kh) {
                case some(k):
                  return k;
                case none: return nil;
              }
            } else {
              close key_opt_list(key_size, cons(kph, kaddrs_b), cons(bbh, busybits_b), cons(kh, key_opts_b));
              append_reverse_take_cons(n,kph,kpt,kaddrs_b);
              append_reverse_take_cons(n,bbh,bbt,busybits_b);
              append_reverse_take_cons(n,kh,kt,key_opts_b);
              return extract_key_at_index(cons(kph,kaddrs_b),
                                          cons(bbh,busybits_b),
                                          cons(kh, key_opts_b),
                                          n-1, bbt, kt);
            }
          }
      }
  }
}

// ---

lemma void reconstruct_key_opt_list(list<char*> kaddrs1, list<char> busybits1, 
                                    list<char*> kaddrs2, list<char> busybits2)
  requires key_opt_list(?key_size, kaddrs1, busybits1, ?key_opts1) &*&
           key_opt_list(key_size, kaddrs2, busybits2, ?key_opts2);
  ensures key_opt_list(key_size,
                       append(reverse(kaddrs1), kaddrs2),
                       append(reverse(busybits1), busybits2),
                       append(reverse(key_opts1), key_opts2));
{
  open key_opt_list(key_size, kaddrs1, busybits1, key_opts1);
  switch(busybits1) {
    case nil:
      assert(kaddrs1 == nil);
      assert(key_opts1 == nil);
      return;
    case cons(bbh, bbt):
      append_reverse_tail_cons_head(kaddrs1, kaddrs2);
      append_reverse_tail_cons_head(busybits1, busybits2);
      append_reverse_tail_cons_head(key_opts1, key_opts2);
      close key_opt_list(key_size, cons(head(kaddrs1), kaddrs2), cons(bbh, busybits2), cons(head(key_opts1), key_opts2));
      reconstruct_key_opt_list(tail(kaddrs1), bbt, 
                               cons(head(kaddrs1), kaddrs2), cons(bbh, busybits2));
  }
}

lemma void recover_key_opt_list(list<char*> kaddrs, list<char> busybits, list<option<list<char> > > key_opts, int n)
  requires key_opt_list(?key_size, reverse(take(n, kaddrs)), reverse(take(n, busybits)), reverse(take(n, key_opts))) &*&
           0 != nth(n, busybits) &*&
           [0.25]chars(nth(n, kaddrs), key_size, ?k) &*&
           nth(n, key_opts) == some(k) &*&
           key_opt_list(key_size, drop(n+1, kaddrs), drop(n+1, busybits), drop(n+1, key_opts)) &*&
           0 <= n &*& n < length(kaddrs) &*&
           n < length(busybits) &*&
           n < length(key_opts);
  ensures key_opt_list(key_size, kaddrs, busybits, key_opts);
{
  close key_opt_list(key_size,
                     cons(nth(n, kaddrs), drop(n+1,kaddrs)),
                     cons(nth(n, busybits), drop(n+1,busybits)),
                     cons(nth(n, key_opts), drop(n+1, key_opts)));
  drop_n_plus_one(n, kaddrs);
  drop_n_plus_one(n, busybits);
  drop_n_plus_one(n, key_opts);
  reconstruct_key_opt_list(reverse(take(n, kaddrs)),
                           reverse(take(n, busybits)),
                           drop(n, kaddrs),
                           drop(n, busybits));
}

// ---

lemma void key_opt_list_find_key(list<option<list<char> > > key_opts, int i, list<char> k)
  requires nth(i, key_opts) == some(k) &*&
           true == opt_no_dups(key_opts) &*&
           0 <= i &*& i < length(key_opts);
  ensures index_of(some(k), key_opts) == i;
{
  switch(key_opts) {
    case nil: return;
    case cons(h,t):
      if (h == some(k)) {
        no_dups_same(key_opts, k, i, 0);
        assert(i == 0);
        return;
      } else {
        key_opt_list_find_key(t, i-1, k);
      }
  }
}

// ---

lemma void no_hash_no_key(list<option<list<char> > > key_opts, list<uint32_t> hashes, list<char> k, int i)
  requires true == hash_list(key_opts, hashes) &*&
           nth(i, hashes) != hash_fp(k) &*&
           0 <= i &*& i < length(key_opts);
  ensures nth(i, key_opts) != some(k);
{
  switch(key_opts) {
    case nil:
      assert(hashes == nil);
      return;
    case cons(kh,kt):
      assert hashes != nil;
      if (i == 0) {
        assert(nth(i, key_opts) == kh);
        if (kh == some(k)) {
          assert(head(hashes) == hash_fp(k));
          nth_0_head(hashes);
          assert(nth(i, hashes) == head(hashes));
          assert(nth(i, hashes) == hash_fp(k));
        }
        return;
      } else {
        nth_cons(i, tail(hashes), head(hashes));
        cons_head_tail(hashes);
        assert(nth(i, hashes) == nth(i-1,tail(hashes)));
        no_hash_no_key(kt, tail(hashes), k, i-1);
      }
  }
}

// ---

lemma void no_bb_no_key(list<option<list<char> > > key_opts, list<char> busybits, int i)
  requires key_opt_list(?key_size, ?kaddrs, busybits, key_opts) &*& 0 <= i &*& i < length(key_opts) &*&
           0 == nth(i, busybits);
  ensures key_opt_list(key_size, kaddrs, busybits, key_opts) &*& nth(i, key_opts) == none;
{
  open key_opt_list(key_size, kaddrs, busybits, key_opts);
  switch(busybits) {
    case nil: ;
    case cons(bbh,bbt):
      if (i == 0) {
        nth_0_head(busybits);
        nth_0_head(key_opts);
      } else {
        no_bb_no_key(tail(key_opts), tail(busybits), i-1);
      }
  }
  close key_opt_list(key_size, kaddrs, busybits, key_opts);
}

// ---

lemma void up_to_neq_non_mem<t>(list<t> l, t x)
  requires true == up_to(nat_of_int(length(l)), (nthProp)(l, (neq)(x)));
  ensures false == mem(x, l);
{
  switch(l) {
    case nil:
    case cons(h,t):
      up_to_nth_uncons(h, t, nat_of_int(length(t)), (neq)(x));
      up_to_neq_non_mem(t, x);
  }
}

lemma void no_key_found<kt>(list<option<kt> > ks, kt k)
  requires true == up_to(nat_of_int(length(ks)), (nthProp)(ks, (neq)(some(k))));
  ensures false == mem(some(k), ks);
{
  up_to_neq_non_mem(ks, some(k));
}

// ---


lemma void hash_for_given_key(list<pair<list<char>, nat> > chains,
                              unsigned shift, unsigned capacity,
                              list<char> k)
  requires true == mem(k, map(fst, chains)) &*&
           true == forall(chains, (has_given_hash)(shift, capacity));
  ensures true == (loop_fp(hash_fp(k), capacity) == shift);
{
  switch(chains) {
    case nil:
    case cons(h,t):
      if (fst(h) == k) {
      } else {
        hash_for_given_key(t, shift, capacity, k);
      }
  }
}

lemma void overshoot_bucket(list<bucket<list<char> > > buckets, unsigned shift, unsigned capacity, list<char> k)
  requires true == key_chains_start_on_hash_fp(buckets, shift, capacity) &*&
           loop_fp(hash_fp(k), capacity) < shift &*& shift <= capacity &*&
           capacity - shift == length(buckets);
  ensures false == exists(buckets, (bucket_has_key_fp)(k));
{
  switch(buckets) {
    case nil: return;
    case cons(bh,bt):
      switch(bh) { case bucket(chains):
        if (bucket_has_key_fp(k, bh)) {
            assert true == mem(k, map(fst, chains));
            assert true == forall(chains, (has_given_hash)(shift, capacity));
            hash_for_given_key(chains, shift, capacity, k);
            assert true == (loop_fp(hash_fp(k), capacity) == shift);
        }
        overshoot_bucket(bt, shift + 1, capacity, k);
      }
  }
}

lemma void no_hash_not_in_this_bucket(list<pair<list<char>, nat> > chains, list<char> k,
                                      unsigned shift, unsigned capacity)
  requires true == forall(chains, (has_given_hash)(shift, capacity)) &&
           shift != loop_fp(hash_fp(k), capacity);
  ensures false == mem(k, map(fst, chains));
{
  switch(chains) {
    case nil:
    case cons(h,t):
      if (fst(h) == k) {
        assert false;
      }
      no_hash_not_in_this_bucket(t, k, shift, capacity);
  }
}

lemma void wrong_hash_no_key(list<char> k, bucket<list<char> > bh, list<bucket<list<char> > > bt,
                             unsigned shift, unsigned capacity)
  requires true == key_chains_start_on_hash_fp(cons(bh,bt), shift, capacity) &*&
           shift != loop_fp(hash_fp(k), capacity);
  ensures false == bucket_has_key_fp(k, bh);
{
  switch(bh) { case bucket(chains):
    no_hash_not_in_this_bucket(chains, k, shift, capacity);
  }
}

lemma void key_is_contained_in_the_bucket_rec(list<bucket<list<char> > > buckets, list<pair<list<char>, nat> > acc,
                                              unsigned shift, unsigned capacity,
                                              list<char> k)
  requires true == key_chains_start_on_hash_fp(buckets, shift, capacity) &*&
           true == buckets_ok_rec(acc, buckets, capacity) &*&
           false == mem(k, map(fst, acc)) &*&
           0 <= shift &*& shift <= loop_fp(hash_fp(k), capacity) &*&
           0 < capacity &*&
           capacity - shift == length(buckets) &*&
           false == mem(k, map(fst, get_wraparound(acc, buckets))) &*&
           buckets != nil;
  ensures loop_fp(hash_fp(k), capacity) - shift < length(buckets) &*&
          mem(some(k), buckets_get_keys_rec_fp(acc, buckets)) ==
          bucket_has_key_fp(k, nth(loop_fp(hash_fp(k), capacity) - shift, buckets));
{
  switch(buckets) {
    case nil: return;
    case cons(bh,bt):
      loop_lims(hash_fp(k), capacity);
      assert true == ((loop_fp(hash_fp(k), capacity) - shift) <= length(buckets));
      if (loop_fp(hash_fp(k), capacity) == shift) {
        if (mem(some(k), buckets_get_keys_rec_fp(acc, buckets))) {
          some_bucket_contains_key_rec(acc, buckets, k);
          switch(bh) { case bucket(chains): }
          overshoot_bucket(bt, shift+1, capacity, k);
          if (bucket_has_key_fp(k, nth(loop_fp(hash_fp(k), capacity) - shift, buckets))) {
          } else {
            assert false;
          }
        } else {
          if (bucket_has_key_fp(k, nth(loop_fp(hash_fp(k), capacity) - shift, buckets))) {
            in_this_bucket_then_in_the_map(buckets,
                                           loop_fp(hash_fp(k), capacity) - shift,
                                           k, capacity, acc);
            assert false;
          } else {

          }
        }
      } else {
        assert true == (shift < loop_fp(hash_fp(k), capacity));
        assert true == (shift + 1 < capacity);
        assert true == (1 < length(buckets));
        assert true == (0 < length(bt));
        switch(bt) {
          case nil:
          case cons(h,t):
        }
        switch(bh) { case bucket(chains): };
        wrong_hash_no_key(k, bh, bt, shift, capacity);
        this_bucket_still_no_key(acc, bh, k);
        advance_acc_still_no_key(acc_at_this_bucket(acc, bh), k);
        key_is_contained_in_the_bucket_rec(bt, advance_acc(acc_at_this_bucket(acc, bh)),
                                           shift + 1, capacity, k);
        no_key_certainly_not_here(acc_at_this_bucket(acc, bh), k);
        assert some(k) != get_current_key_fp(acc_at_this_bucket(acc, bh));
        assert true == (bucket_has_key_fp(k, nth(loop_fp(hash_fp(k), capacity) - shift, buckets)) ==
                        bucket_has_key_fp(k, nth(loop_fp(hash_fp(k), capacity) - shift - 1, bt)));
      }
  }
}

lemma void bucket_has_key_correct_hash(list<bucket<list<char> > > buckets, list<char> k,
                                       unsigned start, unsigned capacity)
  requires true == exists(buckets, (bucket_has_key_fp)(k)) &*&
           true == key_chains_start_on_hash_fp(buckets, start, capacity) &*&
           start + length(buckets) == capacity;
  ensures true == bucket_has_key_fp(k, nth(loop_fp(hash_fp(k), capacity) - start, buckets));
{
  switch(buckets) {
    case nil:
    case cons(bh,bt):
      switch(bh) { case bucket(chains):
        if (bucket_has_key_fp(k, bh)) {
          if (start != loop_fp(hash_fp(k), capacity)) {
            no_hash_not_in_this_bucket(chains, k, start, capacity);
          }
        } else {
          bucket_has_key_correct_hash(bt, k, start + 1, capacity);
          if (loop_fp(hash_fp(k), capacity) < start + 1) {
            overshoot_bucket(bt, start + 1, capacity, k);
          }
        }
      }
  }
}

lemma void key_is_contained_in_the_bucket(list<bucket<list<char> > > buckets,
                                          unsigned capacity, list<char> k)
  requires true == key_chains_start_on_hash_fp(buckets, 0, capacity) &*&
           0 < capacity &*&
           true == buckets_ok(buckets) &*&
           length(buckets) == capacity;
  ensures mem(some(k), buckets_get_keys_fp(buckets)) == bucket_has_key_fp(k, nth(loop_fp(hash_fp(k), capacity), buckets));
{
  loop_lims(hash_fp(k), capacity);
  if (mem(k, map(fst, get_wraparound(nil, buckets)))) {
    key_in_wraparound_then_key_in_a_bucket(buckets, k, nil);
    bucket_has_key_correct_hash(buckets, k, 0, capacity);
    buckets_ok_wraparound_bounded_rec(get_wraparound(nil, buckets), buckets, capacity);
    buckets_ok_get_wraparound_idemp(buckets);
    key_in_wraparound_then_in_bucket(buckets, k);
  } else {
    buckets_ok_get_wraparound_idemp(buckets);
    key_is_contained_in_the_bucket_rec(buckets, get_wraparound(nil, buckets), 0, capacity, k);
  }
}

// ---

lemma void chains_depleted_no_hope(list<bucket<list<char> > > buckets, int i,
                                   int start, list<char> k, unsigned capacity)
  requires buckets != nil &*&
           true == up_to(nat_of_int(i + 1),
                         (byLoopNthProp)(buckets_get_keys_fp(buckets),
                                         (neq)(some(k)),
                                         capacity,
                                         start)) &*&
           true == key_chains_start_on_hash_fp(buckets, 0, capacity) &*&
           true == buckets_ok(buckets) &*&
           0 <= i &*& i < capacity &*&
           0 <= start &*&
           start < capacity &*&
           capacity == length(buckets) &*&
           nth(loop_fp(start + i, capacity), buckets_get_chns_fp(buckets)) == 0;
  ensures false == bucket_has_key_fp(k, nth(start, buckets));
{
  if (bucket_has_key_fp(k, nth(start, buckets))) {
    crossing_chains_keep_key(buckets, i, start, capacity, k);
    assert true == mem(k, map(fst, get_crossing_chains_fp(buckets, loop_fp(start + i, capacity))));
    loop_lims(start + i, capacity);
    no_crossing_chains_here(buckets, loop_fp(start + i, capacity));
    assert get_crossing_chains_fp(buckets, loop_fp(start + i, capacity)) == nil;
  }
}
@*/

static bool find_key(char** kaddrs, char* busybits, uint32_t* hashes, uint32_t* chains, char* key_ptr, size_t key_size, size_t capacity, size_t* out_loc)
/*@ requires mapping(key_size, capacity, kaddrs, busybits, hashes, chains, ?values, ?buckets, ?key_opts, ?map_values, ?map_addrs) &*&
             [?kfr]key_ptr[0..key_size] |-> ?key &*&
             is_pow2(capacity, N63) != none &*&
             *out_loc |-> _; @*/
/*@ ensures mapping(key_size, capacity, kaddrs, busybits, hashes, chains, values, buckets, key_opts, map_values, map_addrs) &*&
            [kfr]key_ptr[0..key_size] |-> key &*&
            *out_loc |-> ?out_n &*&
            mem(some(key), key_opts) ? (true == result &*& out_n == index_of(some(key), key_opts)) :
                                       false == result; @*/
{
  uint32_t key_hash = generic_hash(key_ptr, key_size);
  //@ open mapping(key_size, capacity, kaddrs, busybits, hashes, chains, values, buckets, key_opts, map_values, map_addrs);
  //@ open mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, key_opts, map_values, map_addrs);
  //@ assert kaddrs[0..capacity] |-> ?kaddrs_lst;
  //@ assert busybits[0..capacity] |-> ?busybits_lst;
  //@ assert hashes[0..capacity] |-> ?hashes_lst;
  //@ assert chains[0..capacity] |-> ?chains_lst;
  //@ assert values[0..capacity] |-> ?values_lst;
  //@ open buckets_keys_insync(capacity, chains_lst, buckets, key_opts);
  //@ assert key_opt_list(key_size, kaddrs_lst, busybits_lst, key_opts);
  size_t start = loop(key_hash, capacity);
  size_t i = 0;
  for (; i < capacity; ++i)
    /*@ invariant key_opt_list(key_size, kaddrs_lst, busybits_lst, key_opts) &*&
                  kaddrs[0..capacity] |-> kaddrs_lst &*&
                  busybits[0..capacity] |-> busybits_lst &*&
                  hashes[0..capacity] |-> hashes_lst &*&
                  chains[0..capacity] |-> chains_lst &*&
                  values[0..capacity] |-> values_lst &*&
                  map_valuesaddrs(kaddrs_lst, key_opts, values_lst, map_values, map_addrs) &*&
                  0 <= i &*& i <= capacity &*&
                  [kfr]key_ptr[0..key_size] |-> key &*&
                  hash_fp(key) == key_hash &*&
                  true == hash_list(key_opts, hashes_lst) &*&
                  start == loop_fp(hash_fp(key), capacity) &*&
                  key_opts == buckets_get_keys_fp(buckets) &*&
                  buckets != nil &*&
                  true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), capacity, start)) &*&
                  *out_loc |-> _;
    @*/
    //@ decreases capacity - i;
  {
    size_t index = loop(start + i, capacity);
    char* kp = kaddrs[index];
    char bb = busybits[index];
    uint32_t kh = hashes[index];
    uint32_t chn = chains[index];
    if (bb != 0 && kh == key_hash) {
      //@ close key_opt_list(key_size, nil, nil, nil);
      //@ extract_key_at_index(nil, nil, nil, index, busybits_lst, key_opts);
      //@ append_nil(reverse(take(index, kaddrs_lst)));
      //@ append_nil(reverse(take(index, busybits_lst)));
      //@ append_nil(reverse(take(index, key_opts)));
      if (generic_eq(kp, key_ptr, key_size)) {
        //@ recover_key_opt_list(kaddrs_lst, busybits_lst, key_opts, index);
        //@ open map_valuesaddrs(kaddrs_lst, key_opts, values_lst, map_values, map_addrs);
        //@ assert true == opt_no_dups(key_opts);
        //@ close map_valuesaddrs(kaddrs_lst, key_opts, values_lst, map_values, map_addrs);
        //@ key_opt_list_find_key(key_opts, index, key);
        //@ close buckets_keys_insync(capacity, chains_lst, buckets, key_opts);
        //@ close mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, key_opts, map_values, map_addrs);
        //@ close mapping(key_size, capacity, kaddrs, busybits, hashes, chains, values, buckets, key_opts, map_values, map_addrs);
        *out_loc = index;
        return true;
      }
      //@ recover_key_opt_list(kaddrs_lst, busybits_lst, key_opts, index);
    } else {
      //@ if (bb != 0) no_hash_no_key(key_opts, hashes_lst, key, index);
      //@ if (bb == 0) no_bb_no_key(key_opts, busybits_lst, index);
      if (chn == 0) {
        //@ assert length(chains_lst) == capacity;
        //@ buckets_keys_chns_same_len(buckets);
        //@ assert length(buckets) == capacity;
        //@ no_crossing_chains_here(buckets, index);
        //@ assert nil == get_crossing_chains_fp(buckets, index);
        //@ key_is_contained_in_the_bucket(buckets, capacity, key);
        //@ assert true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), capacity, start));
        //@ assert true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), capacity, loop_fp(hash_fp(key), capacity)));
        //@ assert true == up_to(succ(nat_of_int(i)), (byLoopNthProp)(key_opts, (neq)(some(key)), capacity, loop_fp(hash_fp(key), capacity)));
        //@ assert true == up_to(nat_of_int(i+1), (byLoopNthProp)(key_opts, (neq)(some(key)), capacity, loop_fp(hash_fp(key), capacity)));
        //@ assert buckets != nil;
        //@ chains_depleted_no_hope(buckets, i, loop_fp(hash_fp(key), capacity), key, capacity);
        //@ assert false == mem(some(key), key_opts);
        //@ close buckets_keys_insync(capacity, chains_lst, buckets, key_opts);
        //@ close mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, key_opts, map_values, map_addrs);
        //@ close mapping(key_size, capacity, kaddrs, busybits, hashes, chains, values, buckets, key_opts, map_values, map_addrs);
        return false;
      }
      //@ assert(length(key_opts) == capacity);
    }
    //@ assert(nth(index, key_opts) != some(key));
    //@ assert(true == neq(some(key), nth(index, key_opts)));
    //@ assert(true == neq(some(key), nth(loop_fp(i+start,capacity), key_opts)));
    //@ assert(nat_of_int(i+1) == succ(nat_of_int(i)));
  }
  //@ by_loop_for_all(key_opts, (neq)(some(key)), start, capacity, nat_of_int(capacity));
  //@ no_key_found(key_opts, key);
  //@ close buckets_keys_insync(capacity, chains_lst, buckets, key_opts);
  //@ close mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, key_opts, map_values, map_addrs);
  //@ close mapping(key_size, capacity, kaddrs, busybits, hashes, chains, values, buckets, key_opts, map_values, map_addrs);
  return false;
}

/*@


// ---

fixpoint bool cell_busy(option<list<char> > x) { return x != none; }

lemma void full_size(list<option<list<char> > > key_opts)
  requires true == up_to(nat_of_int(length(key_opts)), (nthProp)(key_opts, cell_busy));
  ensures opts_size(key_opts) == length(key_opts);
{
  switch(key_opts) {
    case nil: return;
    case cons(h,t):
      up_to_nth_uncons(h, t, nat_of_int(length(t)), cell_busy);
      full_size(t);
  }
}

// ---
  
lemma void key_opts_size_limits(list<option<list<char> > > key_opts)
  requires true;
  ensures 0 <= opts_size(key_opts) &*& opts_size(key_opts) <= length(key_opts);
{
  switch(key_opts) {
    case nil: return;
    case cons(h,t):
      key_opts_size_limits(t);
  }
}

lemma void zero_bbs_is_for_empty(list<char> busybits, list<option<list<char> > > key_opts, int i)
  requires key_opt_list(?key_size, ?kaddrs, busybits,  key_opts) &*&
           0 == nth(i, busybits) &*&
           0 <= i &*& i < length(busybits);
  ensures key_opt_list(key_size, kaddrs, busybits, key_opts) &*&
          nth(i, key_opts) == none &*&
          opts_size(key_opts) < length(key_opts);
{
  open key_opt_list(key_size, kaddrs, busybits, key_opts);
  switch(busybits) {
    case nil: break;
    case cons(h,t):
      if (i == 0) {
        assert head(key_opts) == none;
        key_opts_size_limits(tail(key_opts));
      } else {
        nth_cons(i, t, h);
        zero_bbs_is_for_empty(t, tail(key_opts), i-1);
      }
  }
  close key_opt_list(key_size, kaddrs, busybits, key_opts);
}

// ---

lemma void start_Xchain(unsigned capacity, list<uint32_t> chains,  list<bucket<list<char> > > buckets, list<option<list<char> > > key_opts, int start)
  requires buckets_keys_insync(capacity, chains, buckets, key_opts) &*&
           0 <= start &*& start < capacity;
  ensures buckets_keys_insync_Xchain(capacity, chains, buckets, start, start, key_opts);
{
  buckets_keys_chns_same_len(buckets);
  open buckets_keys_insync(capacity, chains, buckets, key_opts);
  add_part_chn_zero_len(buckets_get_chns_fp(buckets), start);
  close buckets_keys_insync_Xchain(capacity, chains, buckets, start, start, key_opts);
}

// ---
  
lemma void bb_nonzero_cell_busy(list<char> busybits, list<option<list<char> > > key_opts, int i)
  requires key_opt_list(?key_size, ?kaddrs, busybits, key_opts) &*& 
           0 != nth(i, busybits) &*&
           0 <= i &*& i < length(busybits);
  ensures key_opt_list(key_size, kaddrs, busybits, key_opts) &*& 
          true == cell_busy(nth(i, key_opts));
  {
    open key_opt_list(key_size, kaddrs, busybits, key_opts);
    switch(busybits) {
      case nil: break;
      case cons(h,t):
      if (i == 0) {
      } else {
        nth_cons(i, t, h);
        bb_nonzero_cell_busy(t, tail(key_opts), i-1);
      }
    }
    close key_opt_list(key_size, kaddrs, busybits, key_opts);
  }
@*/


static size_t find_empty(char* busybits, uint32_t* chains, size_t start, size_t capacity)
/*@ requires mapping_core(?key_size, capacity, ?kaddrs, busybits, ?hashes, ?values, ?key_opts, ?map_values, ?map_addrs) &*&
             chains[0..capacity] |-> ?old_chains_lst &*&
             buckets_keys_insync(capacity, old_chains_lst, ?buckets, key_opts) &*&
             0 <= start &*& start < capacity &*&
             opts_size(key_opts) < capacity &*&
             is_pow2(capacity, N63) != none; @*/
/*@ ensures mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, key_opts, map_values, map_addrs) &*&
            chains[0..capacity] |-> ?new_chains_lst &*&
            buckets_keys_insync_Xchain(capacity, new_chains_lst, buckets, start, result, key_opts) &*&
            nth(result, key_opts) == none &*&
            result < capacity; @*/
{
  //@ open mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, key_opts, map_values, map_addrs);
  //@ start_Xchain(capacity, old_chains_lst, buckets, key_opts, start);
  //@ loop_bijection(start, capacity);
  size_t i = 0;
  for (; i < capacity; ++i)
    /*@ invariant key_opt_list(key_size, ?kaddrs_lst, ?busybits_lst, key_opts) &*&
                  busybits[0..capacity] |-> busybits_lst &*&
                  hashes[0..capacity] |-> ?hashes_lst &*&
                  kaddrs[0..capacity] |-> kaddrs_lst &*&
                  values[0..capacity] |-> ?values_lst &*&
                  chains[0..capacity] |-> ?invariant_chains_lst &*&
                  length(key_opts) == capacity &*&
                  true == hash_list(key_opts, hashes_lst) &*&
                  map_valuesaddrs(kaddrs_lst, key_opts, values_lst, map_values, map_addrs) &*&
                  0 <= i &*& i <= capacity &*&
                  true == up_to(nat_of_int(i),(byLoopNthProp)(key_opts, cell_busy, capacity, start)) &*&
                  buckets_keys_insync_Xchain(capacity, invariant_chains_lst, buckets, start, loop_fp(start + i, capacity), key_opts);
      @*/
    //@ decreases capacity - i;
  {
    size_t index = loop(start + i, capacity);
    //@ assert chains[0..capacity] |-> ?chains_lst;
    //@ open buckets_keys_insync_Xchain(capacity, chains_lst, buckets, start, index, key_opts);
    char bb = busybits[index];
    if (bb == 0) {
      //@ zero_bbs_is_for_empty(busybits_lst, key_opts, index);
      //@ close mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, key_opts, map_values, map_addrs);
      //@ close buckets_keys_insync_Xchain(capacity, chains_lst, buckets, start, index, key_opts);
      return index;
    }
    uint32_t chn = chains[index];
    //@ buckets_keys_chns_same_len(buckets);
    //@ buckets_ok_chn_bound(buckets, index);
    //@ outside_part_chn_no_effect(buckets_get_chns_fp(buckets), start, index, capacity);
    //@ assert chn <= capacity;
    chains[index] = chn + 1;
    //@ bb_nonzero_cell_busy(busybits_lst, key_opts, index);
    //@ assert true == cell_busy(nth(loop_fp(i+start,capacity), key_opts));
    //@ assert nat_of_int(i+1) == succ(nat_of_int(i));
    //@ Xchain_add_one(chains_lst, buckets_get_chns_fp(buckets), start, index < start ? capacity + index - start : index - start, capacity);
    /*@
        if (i + 1 == capacity) {
          by_loop_for_all(key_opts, cell_busy, start, capacity, nat_of_int(capacity));
          full_size(key_opts);
          assert false;
        }
    @*/
    /*@
        if (index < start) {
          if (start + i < capacity) loop_bijection(start + i, capacity);
          loop_injection_n(start + i + 1 - capacity, capacity, 1);
          loop_bijection(start + i + 1 - capacity, capacity);
          loop_injection_n(start + i - capacity, capacity, 1);
          loop_bijection(start + i - capacity, capacity);
        } else {
          if (capacity <= start + i) {
            loop_injection_n(start + i - capacity, capacity, 1);
            loop_bijection(start + i - capacity, capacity);
          }
          loop_bijection(start + i, capacity);
          if (start + i + 1 == capacity) {
            loop_injection_n(start + i + 1 - capacity, capacity, 1);
            loop_bijection(start + i + 1 - capacity, capacity);
          } else {
            loop_bijection(start + i + 1, capacity);
          }
        }
      @*/
    //@ close buckets_keys_insync_Xchain(capacity, chains_lst, buckets, start, index, key_opts);
  }
  //@ by_loop_for_all(key_opts, cell_busy, start, capacity, nat_of_int(capacity));
  //@ full_size(key_opts);
  //@ assert false;
  return 0;
}

/*@
lemma void buckets_remove_key_chains_still_start_on_hash_rec(list<bucket<list<char> > > buckets, size_t capacity, list<char> key, size_t start)
requires true == key_chains_start_on_hash_fp(buckets, start, capacity);
ensures true == key_chains_start_on_hash_fp(buckets_remove_key_fp(buckets, key), start, capacity);
{
  switch(buckets) {
    case nil:
    case cons(h,t):
      switch(h) {
        case bucket(chains):
          forall_filter((has_given_hash)(start, capacity), (not_this_key_pair_fp)(key), chains);
          buckets_remove_key_chains_still_start_on_hash_rec(t, capacity, key, start+1);
      }
  }
}

lemma void buckets_remove_key_chains_still_start_on_hash(list<bucket<list<char> > > buckets, size_t capacity, list<char> key)
requires true == key_chains_start_on_hash_fp(buckets, 0, capacity);
ensures true == key_chains_start_on_hash_fp(buckets_remove_key_fp(buckets, key), 0, capacity);
{
  buckets_remove_key_chains_still_start_on_hash_rec(buckets, capacity, key, 0);
}

// ---

lemma void key_opts_rem_preserves_hash_list(list<option<list<char> > > key_opts, list<uint32_t> hashes, int index)
requires true == hash_list(key_opts, hashes) &*& 0 <= index;
ensures true == hash_list(update(index, none, key_opts), hashes);
{
  switch(key_opts) {
    case nil:
    case cons(h, t):
      if (index != 0) {
        key_opts_rem_preserves_hash_list(t, tail(hashes), index - 1);
      }
  }
}

// ---

lemma void map_drop_key(int index)
requires key_opt_list(?key_size, ?kaddrs, ?busybits, ?key_opts) &*&
         map_valuesaddrs(kaddrs, key_opts, ?values, ?map_values, ?map_addrs) &*&
         0 <= index &*& index < length(key_opts) &*&
         nth(index, key_opts) == some(?key) &*&
         ghostmap_get(map_values, key) != none &*&
         ghostmap_get(map_addrs, key) == some(?key_ptr) &*&
         true == opt_no_dups(key_opts) &*&
         true == ghostmap_distinct(map_values) &*&
         true == ghostmap_distinct(map_addrs);
ensures key_opt_list(key_size, kaddrs, update(index, 0, busybits), update(index, none, key_opts)) &*&
        map_valuesaddrs(kaddrs, update(index, none, key_opts), values, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key)) &*&
        false == mem(some(key), update(index, none, key_opts)) &*&
        [0.25]chars(key_ptr, key_size, key);
{
  open key_opt_list(key_size, kaddrs, busybits, key_opts);
  open map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
  switch(kaddrs) {
    case nil:
    case cons(kaddrsh, kaddrst):
      assert key_opts == cons(?key_optsh, ?key_optst);
      assert values == cons(?valuesh, ?valuest);
      assert map_valuesaddrs(kaddrst, key_optst, valuest, ?map_values_rest, ?map_addrs_rest);
      if (index == 0) {
        assert busybits == cons(?busybitsh, ?busybitst);
        ghostmap_remove_when_present_decreases_length(map_values, key);
        ghostmap_remove_when_present_decreases_length(map_addrs, key);
        close map_valuesaddrs(kaddrs, cons(none, key_optst), values, map_values_rest, map_addrs_rest);
        close key_opt_list(key_size, kaddrs, cons(0, busybitst), cons(none, key_optst));
      } else {
        switch(key_optsh) {
          case none:
            map_drop_key(index - 1);
            assert map_valuesaddrs(kaddrst, update(index - 1, none, key_optst), valuest, ?new_map_values, ?new_map_addrs);
            close map_valuesaddrs(kaddrs, update(index, none, key_opts), values, new_map_values, new_map_addrs);
            close key_opt_list(key_size, kaddrs, update(index, 0, busybits), update(index, none, key_opts));
          case some(kohv):
            if (kohv == key) {
              no_dups_same(key_opts, key, index, 0);
            }
            ghostmap_remove_preserves_other(map_values, kohv, key);
            ghostmap_remove_preserves_other(map_addrs, kohv, key);
            map_drop_key(index - 1);
            ghostmap_remove_order_is_irrelevant(map_values, key, kohv);
            ghostmap_remove_order_is_irrelevant(map_addrs, key, kohv);
            ghostmap_remove_preserves_other(map_values, key, kohv);
            ghostmap_remove_preserves_other(map_addrs, key, kohv);
            close map_valuesaddrs(kaddrs, update(index, none, key_opts), values, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key));
            close key_opt_list(key_size, kaddrs, update(index, 0, busybits), update(index, none, key_opts));
        }
      }
  }
}

// ---

lemma void remove_decreases_key_opts_size(list<option<list<char> > > key_opts, size_t index)
requires 0 <= index &*& index < length(key_opts) &*&
         nth(index, key_opts) != none;
ensures opts_size(update(index, none, key_opts)) == opts_size(key_opts) - 1;
{
  switch(key_opts) {
    case nil:
      assert false;
    case cons(h, t):
      if (index != 0) {
        remove_decreases_key_opts_size(t, index - 1);
      }
  }
}

// ---

lemma void map_values_has_implies_key_opts_has(list<char> key)
requires map_valuesaddrs(?kaddrs, ?key_opts, ?values, ?map_values, ?map_addrs) &*&
         ghostmap_get(map_values, key) != none;
ensures map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs) &*&
        true == mem(some(key), key_opts);
{
  open map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
  switch(kaddrs) {
    case nil:
      assert false;
    case cons(kaddrsh, kaddrst):
      assert key_opts == cons(?key_optsh, ?key_optst);
      switch (key_optsh) {
        case none:
          map_values_has_implies_key_opts_has(key);
        case some(kohv):
          if (kohv != key) {
            ghostmap_remove_preserves_other(map_values, kohv, key);
            map_values_has_implies_key_opts_has(key);
          }
      }
  }
  close map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
}
@*/

static size_t find_key_remove_chain(char** kaddrs, char* busybits, uint32_t* hashes, uint32_t* chains, char* key_ptr, size_t key_size, size_t capacity)
/*@ requires mapping_core(key_size, capacity, kaddrs, busybits, hashes, ?values, ?key_opts, ?map_values, ?map_addrs) &*&
             chains[0..capacity] |-> ?chains_lst &*&
             buckets_keys_insync(capacity, chains_lst, ?buckets, key_opts) &*&
             [?kfr]key_ptr[0..key_size] |-> ?key &*&
             ghostmap_get(map_values, key) != none &*&
             ghostmap_get(map_addrs, key) == some(key_ptr) &*&
             is_pow2(capacity, N63) != none; @*/
/*@ ensures mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, ?new_key_opts, ?new_map_values, ?new_map_addrs) &*&
            false == mem(some(key), new_key_opts) &*&
            new_map_values == ghostmap_remove(map_values, key) &*&
            new_map_addrs == ghostmap_remove(map_addrs, key) &*&
            chains[0..capacity] |-> ?new_chains_lst &*&
            buckets_keys_insync(capacity, new_chains_lst, buckets_remove_key_fp(buckets, key), new_key_opts) &*&
            [kfr+0.25]key_ptr[0..key_size] |-> key &*&
            result == index_of(some(key), key_opts); @*/
{
  uint32_t key_hash = generic_hash(key_ptr, key_size);
  //@ open mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, key_opts, map_values, map_addrs);
  //@ open buckets_keys_insync(capacity, chains_lst, buckets, key_opts);
  //@ assert key_opt_list(key_size, ?kaddrs_lst, ?busybits_lst, key_opts);
  //@ map_values_has_implies_key_opts_has(key);
  size_t i = 0;
  size_t start = loop(key_hash, capacity);
  //@ buckets_keys_chns_same_len(buckets);
  //@ key_is_contained_in_the_bucket(buckets, capacity, key);
  //@ buckets_remove_add_one_chain(buckets, start, key);
  //@ loop_bijection(start, capacity);
  for (; i < capacity; ++i)
    /*@ invariant kaddrs[0..capacity] |-> kaddrs_lst &*&
                  busybits[0..capacity] |-> busybits_lst &*&
                  hashes[0..capacity] |-> ?hashes_lst &*&
                  values[0..capacity] |-> ?values_lst &*&
                  key_opt_list(key_size, kaddrs_lst, busybits_lst, key_opts) &*&
                  map_valuesaddrs(kaddrs_lst, key_opts, values_lst, map_values, map_addrs) &*&
                  true == hash_list(key_opts, hashes_lst) &*&
                  opts_size(key_opts) == length(map_values) &*&
                  chains[0..capacity] |-> chains_lst &*&
                  0 <= i &*& i <= capacity &*&
                  [kfr]key_ptr[0..key_size] |-> key &*&
                  hash_fp(key) == key_hash &*&
                  key_opts == buckets_get_keys_fp(buckets) &*&
                  i <= buckets_get_chain_fp(buckets, key, start) &*&
                  chains_lst == add_partial_chain_fp(loop_fp(start + i, capacity), 
                                                     buckets_get_chain_fp(buckets, key, start) - i, 
                                                     buckets_get_chns_fp(buckets_remove_key_fp(buckets, key))) &*&
                  true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), capacity, start)); @*/
    //@ decreases capacity - i;
  {
    size_t index = loop(start + i, capacity);
    char bb = busybits[index];
    uint32_t kh = hashes[index];
    uint32_t chn = chains[index];
    char* kp = kaddrs[index];
    if (bb != 0 && kh == key_hash) {
      //@ close key_opt_list(key_size, nil, nil, nil);
      //@ extract_key_at_index(nil, nil, nil, index, busybits_lst, key_opts);
      //@ append_nil(reverse(take(index, kaddrs_lst)));
      //@ append_nil(reverse(take(index, busybits_lst)));
      //@ append_nil(reverse(take(index, key_opts)));
      if (generic_eq(kp, key_ptr, key_size)) {
        //@ recover_key_opt_list(kaddrs_lst, busybits_lst, key_opts, index);
        //@ key_opt_list_find_key(key_opts, index, key);
        busybits[index] = 0;
        //@ rem_preserves_opt_no_dups(key_opts, index);
        //@ key_opts_rem_preserves_hash_list(key_opts, hashes_lst, index);
        //@ remove_decreases_key_opts_size(key_opts, index);
        //@ map_drop_key(index);
        //@ close mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, ?new_key_opts, ?new_map_values, ?new_map_addrs);
        //@ chns_after_partial_chain_ended(buckets, key, start, i, capacity);
        //@ buckets_remove_key_still_ok(buckets, key);
        //@ buckets_rm_key_get_keys(buckets, key);
        //@ buckets_remove_key_chains_still_start_on_hash(buckets, capacity, key);
        //@ buckets_remove_key_same_len(buckets, key);
        //@ close buckets_keys_insync(capacity, chains_lst, buckets_remove_key_fp(buckets, key), update(index_of(some(key), key_opts), none, key_opts));
        return index;
      }
      //@ recover_key_opt_list(kaddrs_lst, busybits_lst, key_opts, index);
    } else {
      //@ assert(length(key_opts) == capacity);
      //@ if (bb != 0) no_hash_no_key(key_opts, hashes_lst, key, index);
      //@ if (bb == 0) no_bb_no_key(key_opts, busybits_lst, index);
    }
    //@ buckets_remove_key_same_len(buckets, key);
    //@ buckets_keys_chns_same_len(buckets_remove_key_fp(buckets, key));
    //@ assert nth(index, key_opts) != some(key);
    //@ buckets_get_chain_longer(buckets, start, i, key, capacity);
    //@ assert buckets_get_chain_fp(buckets, key, start) != i;
    //@ buckets_get_chns_nonneg(buckets_remove_key_fp(buckets, key));
    //@ add_part_chn_gt0(index, buckets_get_chain_fp(buckets, key, start) - i, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
    //@ assert 0 < nth(index, chains_lst);
    //@ assert 0 < chn;
    //@ u_integer_limits(&chn);
    chains[index] = chn - 1;
    //@ assert nth(index, key_opts) != some(key);
    //@ assert true == neq(some(key), nth(index, key_opts));
    //@ assert true == neq(some(key), nth(loop_fp(i+start,capacity), key_opts));
    //@ assert nat_of_int(i+1) == succ(nat_of_int(i));
    //@ buckets_keys_chns_same_len(buckets);
    //@ assert length(buckets) == capacity;
    //@ assert length(chains_lst) == length(buckets);
    //@ buckets_remove_key_same_len(buckets, key);
    //@ buckets_keys_chns_same_len(buckets_remove_key_fp(buckets, key));
    //@ add_partial_chain_same_len(start + i, buckets_get_chain_fp(buckets, key, start) - i, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
    //@ loop_fixp(start + i, capacity);
    //@ buckets_ok_get_chain_bounded(buckets, key, start);
    //@ remove_one_cell_from_partial_chain(chains_lst, loop_fp(start + i, capacity), buckets_get_chain_fp(buckets, key, start) - i, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)), capacity);
    //@ assert chains[0..capacity] |-> update(index, nth(index, chains_lst) - 1, add_partial_chain_fp(loop_fp(start + i, capacity), buckets_get_chain_fp(buckets, key, start) - i, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key))));
    //@ assert chains[0..capacity] |-> add_partial_chain_fp(loop_fp(loop_fp(start + i, capacity) + 1, capacity), buckets_get_chain_fp(buckets, key, start) - i - 1, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
    //@ inc_modulo_loop(start + i, capacity);
    //@ assert loop_fp(loop_fp(start + i, capacity) + 1, capacity) == loop_fp(start + i + 1, capacity);
    //@ chains_lst = add_partial_chain_fp(loop_fp(start + i + 1, capacity), buckets_get_chain_fp(buckets, key, start) - i - 1, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
    //@ assert chains[0..capacity] |-> add_partial_chain_fp(loop_fp(start + i + 1, capacity), buckets_get_chain_fp(buckets, key, start) - i - 1, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
  }
  //@ by_loop_for_all(key_opts, (neq)(some(key)), start, capacity, nat_of_int(capacity));
  //@ no_key_found(key_opts, key);
  //@ assert false;
  return 0;
}

/*@
lemma void move_uint(uint32_t* data, uint32_t i, int len)
  requires uints(data, i, ?l1) &*& uints(data + i, len - i, ?l2) &*&
           i < len;
  ensures uints(data, i + 1, append(l1,cons(head(l2),nil))) &*&
          uints(data + i + 1, len - i - 1, tail(l2));
{
  open(uints(data, i, l1));
  switch(l1) {
    case nil:
      open(uints(data, len-i, l2));
      close(uints(data, 1, cons(head(l2),nil)));
    case cons(h,t):
      move_uint(data+1, i-1, len-1);
  }
  close(uints(data, i+1, append(l1, cons(head(l2),nil))));
}

lemma void move_bb(char* data, char i, int len)
  requires chars(data, i, ?l1) &*& chars(data + i, len - i, ?l2) &*&
           i < len;
  ensures chars(data, i + 1, append(l1,cons(head(l2),nil))) &*&
          chars(data + i + 1, len - i - 1, tail(l2));
{
  open(chars(data, i, l1));
  switch(l1) {
    case nil:
      open(chars(data, len-i, l2));
      close(chars(data, 1, cons(head(l2),nil)));
    case cons(h,t):
      move_bb(data+1, i-1, len-1);
  }
  close(chars(data, i+1, append(l1, cons(head(l2),nil))));
}

// ---

lemma void extend_repeat_n<t>(nat len, t extra, t z)
  requires true;
  ensures update(int_of_nat(len), z, append(repeat_n(len, z), cons(extra, nil))) == repeat_n(succ(len), z);
{
  switch(len) {
    case zero: return;
    case succ(l):
      extend_repeat_n(l, extra, z);
  }
}

// ---

lemma void nat_len_of_non_nil<t>(t h, list<t> t)
  requires true;
  ensures nat_of_int(length(cons(h, t)) - 1) == nat_of_int(length(t)) &*&
          nat_of_int(length(cons(h, t))) == succ(nat_of_int(length(t)));
{
  int l = length(cons(h,t));
  assert(0 < l);
  switch(nat_of_int(l)) {
    case zero:
      note(int_of_nat(zero) == l);
      assert(false);
      return;
    case succ(lll):
      return;
  }
}

lemma void produce_key_opt_list(size_t key_size, list<uint32_t> hashes, list<char*> kaddrs)
  requires length(hashes) == length(kaddrs);
  ensures key_opt_list(key_size, kaddrs, repeat_n(nat_of_int(length(kaddrs)), 0), repeat_n(nat_of_int(length(kaddrs)), none)) &*&
          length(kaddrs) == length(repeat_n(nat_of_int(length(kaddrs)), none));
{
  switch(kaddrs) {
    case nil:
      close key_opt_list(key_size, kaddrs, repeat_n(nat_of_int(length(kaddrs)), 0), repeat_n(nat_of_int(length(kaddrs)), none));
      return;
    case cons(kaddrh,kaddrt):
      switch(hashes) {
        case nil: break;
        case cons(hh,ht): break;
      }
      assert(hashes != nil);
      produce_key_opt_list(key_size, tail(hashes), kaddrt);
      nat_len_of_non_nil(kaddrh,kaddrt);
      close key_opt_list(key_size, kaddrs, repeat_n(nat_of_int(length(kaddrs)), 0), repeat_n(nat_of_int(length(kaddrs)), none));
      return;
  }
}

// ---

lemma void kopts_size_0_when_empty(list<option<list<char> > > kopts)
requires true == forall(kopts, (eq)(none));
ensures opts_size(kopts) == 0;
{
  switch(kopts) {
    case nil:
    case cons(h, t):
      kopts_size_0_when_empty(t);
  }
}

// ---

lemma void confirm_hash_list_for_nones(list<unsigned> hashes)
  requires true;
  ensures true == hash_list(repeat_n(nat_of_int(length(hashes)), none), hashes);
{
  switch(hashes) {
    case nil:
      return;
    case cons(h,t):
      confirm_hash_list_for_nones(t);
      nat_len_of_non_nil(h,t);
      assert(tail(repeat_n(nat_of_int(length(hashes)), none)) == repeat_n(nat_of_int(length(t)), none));
      return;
  }
}

// ---

lemma void nat_gt_zero_not_zero(int n)
  requires n > 0;
  ensures nat_of_int(n) != zero;
{
  assert int_of_nat(nat_of_int(n)) == n;
  assert int_of_nat(nat_of_int(n)) != 0;
  assert nat_of_int(n) != zero;
}

lemma void empty_keychains_start_on_hash(nat len, int pos, unsigned capacity)
  requires 0 < capacity;
  ensures true == key_chains_start_on_hash_fp(empty_buckets_fp<list<char> >(len), pos, capacity);
{
  switch(len) {
    case zero:
    case succ(n):
      empty_keychains_start_on_hash(n, pos + 1, capacity);
  }
}

lemma void empty_buckets_insync(list<uint32_t> chains, unsigned capacity)
  requires chains == repeat_n(nat_of_int(capacity), 0) &*&
           0 < capacity;
  ensures buckets_keys_insync(capacity, chains,
                              empty_buckets_fp<list<char> >(nat_of_int(capacity)),
                              repeat_n(nat_of_int(capacity), none));
{
  empty_buckets_chns_zeros<list<char> >(nat_of_int(capacity));
  nat_gt_zero_not_zero(capacity);
  assert nat_of_int(capacity) != zero;
  empty_buckets_ok<list<char> >(nat_of_int(capacity));
  empty_buckets_ks_none<list<char> >(nat_of_int(capacity));
  empty_keychains_start_on_hash(nat_of_int(capacity), 0, capacity);
  repeat_n_length(nat_of_int(capacity), bucket(nil));
  assert length(empty_buckets_fp<list<char> >(nat_of_int(capacity))) == int_of_nat(nat_of_int(capacity));
  assert length(empty_buckets_fp<list<char> >(nat_of_int(capacity))) == capacity;
  close buckets_keys_insync(capacity, chains, empty_buckets_fp<list<char> >(nat_of_int(capacity)), repeat_n(nat_of_int(capacity), none));
}

// ---

lemma void repeat_none_is_opt_no_dups<t>(nat n, list<option<t> > opts)
  requires opts == repeat_n(n, none);
  ensures true == opt_no_dups(opts);
{
  switch(n) {
    case zero:
      assert opts == nil;
    case succ(p):
      assert opts == cons(?optsh, ?optst);
      repeat_none_is_opt_no_dups(p, optst);
      assert optsh == none;
  }
}

lemma void produce_empty_map_valuesaddrs(size_t capacity, list<char*> kaddrs, list<uint64_t> values)
  requires length(kaddrs) == length(values) &*& length(kaddrs) == capacity;
  ensures map_valuesaddrs(kaddrs, repeat_n(nat_of_int(capacity), none), values, nil, nil);
{
  switch(kaddrs) {
    case nil:
      length_0_nil(values);
      close map_valuesaddrs(kaddrs, repeat_n(nat_of_int(capacity), none), values, nil, nil);
    case cons(kh,kt):
      assert values == cons(?vh,?vt);
      assert capacity > 0;
      repeat_n_length(nat_of_int(capacity), none);
      assert repeat_n(nat_of_int(capacity), none) == cons(?noh, ?not);
      repeat_n_is_n(nat_of_int(capacity), none);
      assert noh == none;
      assert head(repeat_n(nat_of_int(capacity), none)) == none;
      produce_empty_map_valuesaddrs(capacity - 1, kt, vt);
      repeat_n_tail(nat_of_int(capacity), none);
      assert not == repeat_n(nat_of_int(capacity-1), none);
      assert true == distinct(nil);
      close map_valuesaddrs(kaddrs, repeat_n(nat_of_int(capacity), none), values, nil, nil);
  }
}
@*/

struct os_map* os_map_init(size_t key_size, size_t capacity)
/*@ requires capacity < (SIZE_MAX / 8) &*&
             key_size > 0; @*/
/*@ ensures result == NULL ? true : mapp(result, key_size, capacity, nil, nil); @*/
{

  // Check that capacity is a power of 2
  if (capacity == 0 || (capacity & (capacity - 1)) != 0) {
      return (struct os_map*) NULL;
  }
  //@ check_pow2_valid(capacity);

  struct os_map* map = (struct os_map*) malloc(sizeof(struct os_map));
  //@ mul_bounds(capacity, SIZE_MAX / 8, sizeof(char*), 8);
  char** kaddrs = (char**) malloc(capacity * sizeof(char*));
  char* busybits = (char*) malloc(capacity * sizeof(char));
  uint32_t* hashes = (uint32_t*) malloc(capacity * sizeof(uint32_t));
  uint32_t* chains = (uint32_t*) malloc(capacity * sizeof(uint32_t));
  uint64_t* values = (uint64_t*) malloc(capacity * sizeof(uint64_t));

  if(map == NULL || kaddrs == NULL || busybits == NULL || hashes == NULL || chains == NULL || values == NULL) {
    if(map != NULL) {
      free(map);
    }
    if(kaddrs != NULL) {
      free(kaddrs);
    }
    if(busybits != NULL) {
      free(busybits);
    }
    if(hashes != NULL) {
      free(hashes);
    }
    if(chains != NULL) {
      free(chains);
    }
    if(values != NULL) {
      free(values);
    }
    return NULL;
  }

  //@ assert kaddrs[0..capacity] |-> ?kaddrs_lst;
  //@ assert busybits[0..capacity] |-> ?busybits_lst;
  //@ assert hashes[0..capacity] |-> ?hashes_lst;
  //@ assert chains[0..capacity] |-> ?chains_lst;
  //@ assert values[0..capacity] |-> ?values_lst;
  size_t i = 0;
  for (; i < capacity; ++i)
    /*@ invariant busybits[0..i] |-> repeat_n(nat_of_int(i), 0) &*&
                  busybits[i..capacity] |-> drop(i, busybits_lst) &*&
                  chains[0..i] |-> repeat_n(nat_of_int(i), 0) &*&
                  chains[i..capacity] |-> drop(i, chains_lst) &*&
                  0 <= i &*& i <= capacity; @*/
    //@ decreases capacity - i;
  {
    //@ move_bb(busybits, i, capacity);
    //@ move_uint(chains, i, capacity);
    //@ extend_repeat_n(nat_of_int(i), head(drop(i, busybits_lst)), 0);
    //@ extend_repeat_n(nat_of_int(i), head(drop(i, chains_lst)), 0);
    busybits[i] = 0;
    chains[i] = 0;
    //@ assert(succ(nat_of_int(i)) == nat_of_int(i+1));
    //@ tail_drop(busybits_lst, i);
    //@ tail_drop(chains_lst, i);
  }
  //@ open chars(busybits + i, capacity - i, drop(i,busybits_lst));
  //@ produce_key_opt_list(key_size, hashes_lst, kaddrs_lst);
  //@ assert key_opt_list(key_size, kaddrs_lst, _, ?kopts);
  //@ repeat_n_contents(nat_of_int(length(kaddrs_lst)), none);
  //@ kopts_size_0_when_empty(kopts);
  //@ assert chains[0..capacity] |-> ?zeroed_chains_lst;
  //@ empty_buckets_insync(zeroed_chains_lst, capacity);
  //@ produce_empty_map_valuesaddrs(capacity, kaddrs_lst, values_lst);
  //@ confirm_hash_list_for_nones(hashes_lst);
  //@ repeat_none_is_opt_no_dups(nat_of_int(length(kaddrs_lst)), kopts);
  //@ close mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, kopts, nil, nil);
  //@ close mapping(key_size, capacity, kaddrs, busybits, hashes, chains, values, _, kopts, nil, nil);

  map->kaddrs = kaddrs;
  map->busybits = busybits;
  map->hashes = hashes;
  map->chains = chains;
  map->values = values;
  map->capacity = capacity;
  map->key_size = key_size;

  //@ close mapp(map, key_size, capacity, nil, nil);
  return map;
}

/*@
lemma void map_values_reflects_keyopts_mem<k,v>(list<char> key, int idx)
requires map_valuesaddrs(?kaddrs, ?key_opts, ?values, ?map_values, ?map_addrs) &*&
         true == ghostmap_distinct(map_values) &*&
         true == mem(some(key), key_opts) &*&
         idx == index_of(some(key), key_opts);
ensures map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs) &*&
        ghostmap_get(map_values, key) == some(nth(idx, values));
{
  open map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
  switch(kaddrs) {
    case nil:
      assert false;
    case cons(kaddrsh, kaddrst):
      assert key_opts == cons(?key_optsh, ?key_optst);
      if (idx != 0) {
        map_values_reflects_keyopts_mem(key, idx - 1);
        switch(key_optsh) {
          case none:
          case some(kohv):
            ghostmap_remove_preserves_other(map_values, kohv, key);
        }
      }
      close map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
  }
}     

// ---

lemma void key_opts_has_not_implies_map_values_has_not(list<char> key)
requires map_valuesaddrs(?kaddrs, ?key_opts, ?values, ?map_values, ?map_addrs) &*&
         false == mem(some(key), key_opts);
ensures map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs) &*&
        ghostmap_get(map_values, key) == none;
{
  open map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
  switch(kaddrs) {
    case nil:
    case cons(kaddrsh, kaddrst):
      assert key_opts == cons(?key_optsh, ?key_optst);
      key_opts_has_not_implies_map_values_has_not(key);
      switch (key_optsh) {
        case none:
        case some(kohv):
          ghostmap_remove_preserves_other(map_values, kohv, key);
      }
  }
  close map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
}
@*/

bool os_map_get(struct os_map* map, char* key_ptr, uint64_t* value_out)
/*@ requires mapp(map, ?key_size, ?capacity, ?map_values, ?map_addrs) &*&
             chars(key_ptr, key_size, ?key) &*&
             *value_out |-> _; @*/
/*@ ensures mapp(map, key_size, capacity, map_values, map_addrs) &*&
            chars(key_ptr, key_size, key) &*&
            switch(ghostmap_get(map_values, key)) {
              case none: return result == false &*& *value_out |-> _;
              case some(v): return result == true &*& *value_out |-> v;
            }; @*/
{
  //@ open mapp(map, key_size, capacity, map_values, map_addrs);
  
  size_t index;
  bool has = find_key(map->kaddrs, map->busybits, map->hashes, map->chains, key_ptr, map->key_size, map->capacity, &index);
  
  //@ open mapping(key_size, capacity, map->kaddrs, map->busybits, map->hashes, map->chains, map->values, ?buckets, ?key_opts, map_values, map_addrs);
  //@ open mapping_core(key_size, capacity, map->kaddrs, map->busybits, map->hashes, map->values, key_opts, map_values, map_addrs);
  if (has)
  {
    //@ map_values_reflects_keyopts_mem(key, index);
    *value_out = map->values[index];
  }
  else
  {
    //@ key_opts_has_not_implies_map_values_has_not(key);
  }
  //@ close mapping_core(key_size, capacity, map->kaddrs, map->busybits, map->hashes, map->values, key_opts, map_values, map_addrs);
  //@ close mapping(key_size, capacity, map->kaddrs, map->busybits, map->hashes, map->chains, map->values, buckets, key_opts, map_values, map_addrs);
  
  //@ close mapp(map, key_size, capacity, map_values, map_addrs);
  return has;
}

/*@
lemma void put_keeps_key_opt_list(list<char*> kaddrs, list<char> busybits, list<option<list<char> > > key_opts, int index, char* key, list<char> k)
  requires key_opt_list(?key_size, kaddrs, busybits, key_opts) &*&
           [0.25]chars(key, key_size, k) &*&
           0 <= index &*& index < length(busybits) &*&
           nth(index, key_opts) == none;
  ensures key_opt_list(key_size, update(index, key, kaddrs), update(index, 1, busybits), update(index, some(k), key_opts));
{
  open key_opt_list(key_size, kaddrs, busybits, key_opts);
  switch(busybits) {
    case nil:
      break;
    case cons(bbh, bbt):
      if (index == 0) {
        tail_of_update_0(kaddrs, key);
        tail_of_update_0(key_opts, some(k));
        head_update_0(key, kaddrs);
      } else {
        put_keeps_key_opt_list(tail(kaddrs), bbt, tail(key_opts), index-1, key, k);
        cons_head_tail(kaddrs);
        cons_head_tail(key_opts);
        update_tail_tail_update(head(kaddrs), tail(kaddrs), index, key);
        update_tail_tail_update(head(key_opts), tail(key_opts), index, some(k));
        update_tail_tail_update(bbh, bbt, index, 1);
      }
      update_non_nil(kaddrs, index, key);
      update_non_nil(key_opts, index, some(k));
  }
  close key_opt_list(key_size, update(index, key, kaddrs), update(index, 1, busybits), update(index, some(k), key_opts));
}

// ---

lemma void map_values_has_not_implies_key_opts_has_not(list<pair<list<char>, uint64_t> > map_values, list<option<list<char> > > key_opts, list<char> key)
requires map_valuesaddrs(?kaddrs, key_opts, ?values, map_values, ?map_addrs) &*&
         ghostmap_get(map_values, key) == none;
ensures map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs) &*&
        false == mem(some(key), key_opts);
{
  switch(key_opts) {
    case nil:
    case cons(key_optsh, key_optst):
      switch(key_optsh) {
        case none:
          open map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
          map_values_has_not_implies_key_opts_has_not(map_values, key_optst, key);
          close map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
        case some(kohv):
          open map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
          assert values == cons(?valuesh, ?valuest);
          assert map_valuesaddrs(?kaddrst, key_optst, valuest, ?map_values_rest, ?map_addrs_rest);
          ghostmap_remove_preserves_other(map_values, get_some(key_optsh), key);
          map_values_has_not_implies_key_opts_has_not(map_values_rest, key_optst, key);
          close map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
      }
  }
}

// ---

lemma void buckets_put_chains_still_start_on_hash(list<bucket<list<char> > > buckets, list<char> k, int shift,
                                                  int start, int dist, unsigned capacity)
  requires true == key_chains_start_on_hash_fp(buckets, shift, capacity) &*&
           loop_fp(hash_fp(k), capacity) == start + shift &*&
           0 <= start &*& start < length(buckets) &*&
           0 <= dist &*& dist < capacity;
  ensures true == key_chains_start_on_hash_fp(buckets_put_key_fp(buckets, k, start, dist), shift, capacity);
{
  switch(buckets) {
    case nil:
    case cons(h,t):
      switch(h) {
        case bucket(chains):
          if (start == 0) {
            assert true == has_given_hash(shift, capacity, pair(k, nat_of_int(dist)));
          } else {
            buckets_put_chains_still_start_on_hash(t, k, shift + 1, start - 1, dist, capacity);
          }
      }
  }
}

lemma void buckets_keys_put_key_insync(unsigned capacity, list<int> chains, int start,
                                       int fin, list<char> k, list<option<list<char> > > key_opts)
  requires buckets_keys_insync_Xchain(capacity, chains, ?buckets, start, fin, key_opts) &*&
           0 <= start &*& start < capacity &*&
           0 <= fin &*& fin < capacity &*&
           false == mem(k, buckets_all_keys_fp(buckets)) &*&
           start == loop_fp(hash_fp(k), capacity) &*&
           nth(fin, buckets_get_keys_fp(buckets)) == none;
  ensures buckets_keys_insync(capacity, chains,
                              buckets_put_key_fp(buckets, k, start,
                                                 loop_fp(capacity + fin - start,
                                                         capacity)),
                              update(fin, some(k), key_opts));
{
  open buckets_keys_insync_Xchain(capacity, chains, buckets, start, fin, key_opts);
  int dist = 0;
  if (fin == 0 && start != 0) {
    dist = capacity - start;
    loop_bijection(capacity + fin - start, capacity);
    loop_injection(0, capacity);
    loop_bijection(0, capacity);
  } else if (fin < start) {
    dist = fin + capacity - start;
    loop_bijection(fin - start + capacity, capacity);
    loop_injection_n(fin + capacity, capacity, -1);
  } else {
    dist = fin - start;
    loop_injection_n(fin - start + capacity, capacity, -1);
    loop_bijection(fin - start, capacity);
  }
  buckets_add_part_get_chns(buckets, k, start, dist);
  assert loop_fp(capacity + fin - start, capacity) == dist;
  loop_bijection(fin, capacity);
  assert loop_fp(start + dist, capacity) == fin;
  buckets_put_still_ok(buckets, k, start, dist);
  buckets_put_chains_still_start_on_hash(buckets, k, 0, start, dist, length(buckets));
  buckets_put_update_ks(buckets, key_opts, k, start, dist);
  assert length(buckets) == capacity;
  buckets_put_key_length_unchanged(buckets, k, start, dist);
  assert length(buckets_put_key_fp(buckets, k, start, dist)) == capacity;
  close buckets_keys_insync(capacity, chains,
                            buckets_put_key_fp(buckets, k, start, dist),
                            update(fin, some(k), key_opts));
}

// ---

lemma void put_preserves_no_dups(list<option<list<char> > > key_opts, int i, list<char> k)
  requires false == mem(some(k), key_opts) &*& 
           true == opt_no_dups(key_opts);
  ensures true == opt_no_dups(update(i, some(k), key_opts));
{
  switch(key_opts) {
    case nil: break;
    case cons(h,t):
      if (i == 0) {
      } else {
        put_preserves_no_dups(t, i-1, k);
        if (h == none) {
        } else {
          assert(false == mem(h, t));
          update_irrelevant_cell(h, i-1, some(k), t);
          assert(false == mem(h, update(i-1, some(k), t)));
        }
      }
  }
}

// ---

lemma void put_updates_valuesaddrs(size_t index, char* key_ptr, list<char> key, uint64_t value)
  requires map_valuesaddrs(?kaddrs, ?key_opts, ?values, ?map_values, ?map_addrs) &*&
           0 <= index &*& index < length(key_opts) &*&
           nth(index, key_opts) == none &*&
           false == mem(some(key), key_opts) &*&
           ghostmap_get(map_values, key) == none &*&
           ghostmap_get(map_addrs, key) == none;
  ensures map_valuesaddrs(update(index, key_ptr, kaddrs),
                          update(index, some(key), key_opts),
                          update(index, value, values),
                          ghostmap_set(map_values, key, value),
                          ghostmap_set(map_addrs, key, key_ptr));
{
  open map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
  switch(key_opts) {
    case nil:
    case cons(key_optsh, key_optst):
      if (index != 0) {
        assert kaddrs == cons(?kaddrsh, ?kaddrst);
        switch(key_optsh) {
          case none:
          case some(kohv):
            ghostmap_remove_preserves_other(map_values, kohv, key);
            ghostmap_remove_preserves_other(map_addrs, kohv, key);
        }
        put_updates_valuesaddrs(index - 1, key_ptr, key, value);
      }
  }
  close map_valuesaddrs(update(index, key_ptr, kaddrs),
                        update(index, some(key), key_opts),
                        update(index, value, values),
                        ghostmap_set(map_values, key, value),
                        ghostmap_set(map_addrs, key, key_ptr));
}

// ---

lemma void put_preserves_hash_list(list<option<list<char> > > key_opts, list<uint32_t> hashes, size_t index, list<char> k, uint32_t hash)
  requires true == hash_list(key_opts, hashes) &*&
           hash_fp(k) == hash &*&
           0 <= index;
  ensures true == hash_list(update(index, some(k), key_opts), update(index, hash, hashes));
{
  switch(key_opts) {
    case nil: break;
    case cons(h,t):
      update_non_nil(hashes, index, hash);
      if (index == 0) {
        head_update_0(some(k), key_opts);
        head_update_0(hash, hashes);
        tail_of_update_0(hashes, hash);
        assert update(0, hash, hashes) != nil;
        assert true == hash_list(t, tail(update(0, hash, hashes)));
        assert head(update(0, hash, hashes)) == hash_fp(get_some(head(update(0, some(k), key_opts))));
      } else {
        put_preserves_hash_list(t, tail(hashes), index-1, k, hash);
        cons_head_tail(hashes);
        update_tail_tail_update(head(hashes), tail(hashes), index, hash);
        update_tail_tail_update(h, t, index, some(k));
      }
  }
}

// ---

lemma void put_increases_key_opts_size(list<option<list<char> > > key_opts, size_t index, list<char> key)
requires 0 <= index &*& index < length(key_opts) &*&
         nth(index, key_opts) == none;
ensures opts_size(update(index, some(key), key_opts)) == opts_size(key_opts) + 1;
{
  switch(key_opts) {
    case nil:
      assert false;
    case cons(h, t):
      if (index != 0) {
        put_increases_key_opts_size(t, index - 1, key);
      }
  }
}
@*/

void os_map_set(struct os_map* map, char* key_ptr, uint64_t value)
/*@ requires mapp(map, ?key_size, ?capacity, ?map_values, ?map_addrs) &*&
             [0.25]chars(key_ptr, key_size, ?key) &*&
             length(map_values) < capacity &*&
             ghostmap_get(map_values, key) == none &*&
             ghostmap_get(map_addrs, key) == none; @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_set(map_values, key, value), ghostmap_set(map_addrs, key, key_ptr)); @*/
{
  //@ open mapp(map, key_size, capacity, map_values, map_addrs);
  uint32_t hash = generic_hash(key_ptr, map->key_size);
  
  //@ open mapping(key_size, capacity, ?kaddrs, ?busybits, ?hashes, ?chains, ?values, ?buckets, ?key_opts, map_values, map_addrs);
  
  // This mess is somehow necessary so VeriFast doesn't get confused due to field dereferences
  //@ assert map->kaddrs == kaddrs && map->busybits == busybits && map->hashes == hashes && map->chains == chains && map->values == values;
  //@ open mapping_core(key_size, capacity, kaddrs, busybits, map->hashes, values, key_opts, map_values, map_addrs);
  //@ assert map->capacity == capacity;
  //@ close mapping_core(key_size, capacity, kaddrs, busybits, map->hashes, values, key_opts, map_values, map_addrs);
  
  size_t start = loop(hash, map->capacity);
  size_t index = find_empty(map->busybits, map->chains, start, map->capacity);
  
  //@ open mapping_core(key_size, capacity, kaddrs, busybits, map->hashes, values, key_opts, map_values, map_addrs);
  //@ assert kaddrs[0..capacity] |-> ?kaddrs_lst;
  //@ assert busybits[0..capacity] |-> ?busybits_lst;
  //@ assert values[0..capacity] |-> ?values_lst;
  //@ assert hashes[0..capacity] |-> ?hashes_lst;
  //@ assert chains[0..capacity] |-> ?chains_lst;
  
  //@ map_values_has_not_implies_key_opts_has_not(map_values, key_opts, key);

  map->kaddrs[index] = key_ptr;
  map->busybits[index] = 1;
  map->hashes[index] = hash;
  map->values[index] = value;
  
  //@ open buckets_keys_insync_Xchain(capacity, ?cur_chains, buckets, ?cur_start, ?cur_fin, key_opts);
  //@ assert buckets_get_keys_fp(buckets) == key_opts;
  //@ close buckets_keys_insync_Xchain(capacity, cur_chains, buckets, cur_start, cur_fin, key_opts);
  //@ no_key_in_ks_no_key_in_buckets(buckets, key);
  //@ buckets_keys_put_key_insync(capacity, chains_lst, start, index, key, key_opts);
  //@ put_keeps_key_opt_list(kaddrs_lst, busybits_lst, key_opts, index, key_ptr, key);
  //@ put_updates_valuesaddrs(index, key_ptr, key, value);
  //@ put_preserves_no_dups(key_opts, index, key);
  //@ put_preserves_hash_list(key_opts, hashes_lst, index, key, hash);
  //@ list<option<list<char> > > new_key_opts = update(index, some(key), key_opts);
  //@ put_increases_key_opts_size(key_opts, index, key);

  //@ open map_valuesaddrs(?new_kaddrs, new_key_opts, ?new_values, ?new_map_values, ?new_map_addrs);
  //@ assert length(new_map_values) == length(new_map_addrs);
  //@ close map_valuesaddrs(new_kaddrs, new_key_opts, new_values, new_map_values, new_map_addrs);

  //@ close mapping_core(key_size, capacity, kaddrs, busybits, hashes, values, new_key_opts, new_map_values, new_map_addrs);
  //@ close mapping(key_size, capacity, kaddrs, busybits, hashes, chains, values, _, new_key_opts, new_map_values, new_map_addrs);
  //@ close mapp(map, key_size, capacity, new_map_values, new_map_addrs);
}

void os_map_remove(struct os_map* map, char* key_ptr)
/*@ requires mapp(map, ?key_size, ?capacity, ?map_values, ?map_addrs) &*&
             [?frac]chars(key_ptr, key_size, ?key) &*&
             frac != 0.0 &*&
             ghostmap_get(map_values, key) != none &*&
             ghostmap_get(map_addrs, key) == some(key_ptr); @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key)) &*&
           [frac + 0.25]chars(key_ptr, key_size, key); @*/
{
  //@ open mapp(map, key_size, capacity, map_values, map_addrs);
  //@ open mapping(key_size, capacity, ?kaddrs, ?busybits, ?hashes, ?chains, ?values, ?buckets, ?key_opts, map_values, map_addrs);
  find_key_remove_chain(map->kaddrs, map->busybits, map->hashes, map->chains, key_ptr, map->key_size, map->capacity);
  //@ close mapping(key_size, capacity, kaddrs, busybits, hashes, _, values, _, _, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key));
  //@ close mapp(map, key_size, capacity, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key));
}