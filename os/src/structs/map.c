#include "os/structs/map.h"

#include "os/memory.h"
#include "generic_ops.h"

//@ #include "proof/chain-buckets.gh"
//@ #include "proof/listexex.gh"
//@ #include "proof/modulo.gh"
//@ #include "proof/mod-pow2.gh"
//@ #include "proof/nth-prop.gh"
//@ #include "proof/sizeex.gh"
//@ #include "proof/stdex.gh"

// !!! IMPORTANT !!!
// To verify, 'default_value_eq_zero' needs to be turned from a lemma_auto to a lemma in prelude_core.gh, see verifast issue 68

struct os_map {
  void** kaddrs;
  bool* busybits;
  hash_t* hashes;
  size_t* chains;
  void** values;
  size_t key_size;
  size_t capacity;
};

/*@
  fixpoint size_t opts_size(list<option<list<char> > > opts) {
    switch(opts) {
      case nil: return 0;
      case cons(h,t): return (h == none ? 0 : 1) + opts_size(t);
    }
  }

  // Addresses + busybits => key options
  predicate key_opt_list(size_t key_size, list<void*> kaddrs, list<bool> busybits;
                         list<option<list<char> > > key_opts) =
    switch(busybits) {
      case nil:
        return kaddrs == nil &*& key_opts == nil;
      case cons(bbh, bbt):
        return kaddrs == cons(?kaddrsh, ?kaddrst) &*&
               key_opt_list(key_size, kaddrst, bbt, ?key_optst) &*&
               bbh ? ([0.25]chars(kaddrsh, key_size, ?key_optsh) &*& key_opts == cons(some(key_optsh), key_optst)) : (key_opts == cons(none, key_optst));
    };

  // Key options => hashes
  // NOTE: It's important that we say nothing about hashes of none keys, which is why this can't return a list<hash_t> (which would need to reason about this info)
  predicate hash_list(list<option<list<char> > > key_opts, list<hash_t> hashes) =
    switch(key_opts) {
      case nil:
        return hashes == nil;
      case cons(koh, kot):
        return hashes == cons(?hh, ?ht) &*&
               hash_list(kot, ht) &*&
               switch(koh) {
                 case none: return true;
                 case some(hv): return hh == hash_fp(hv);
               };
    };

  fixpoint bool has_given_hash(size_t pos, size_t capacity, pair<list<char>, nat> chain) {
    return pos == loop_fp(hash_fp(fst(chain)), capacity);
  }

  fixpoint bool key_chains_start_on_hash_fp(list<bucket<list<char> > > buckets, size_t pos, size_t capacity) {
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
  predicate buckets_keys_insync(size_t capacity, list<hash_t> chains, list<bucket<list<char> > > buckets;
                                list<option<list<char> > > key_opts) =
    chains == buckets_get_chns_fp(buckets) &*&
    true == buckets_ok(buckets) &*&
    true == key_chains_start_on_hash_fp(buckets, 0, capacity) &*&
    key_opts == buckets_get_keys_fp(buckets) &*&
    length(buckets) == capacity;

  // Partial: Chains + buckets => key options
  predicate buckets_keys_insync_Xchain(size_t capacity, list<hash_t> chains, list<bucket<list<char> > > buckets, size_t start, size_t fin; list<option<list<char> > > key_opts) =
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
  predicate map_valuesaddrs(list<void*> kaddrs, list<option<list<char> > > key_opts, list<void*> values,
                            list<pair<list<char>, void*> > map_values, list<pair<list<char>, void*> > map_addrs) =
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

               true == ghostmap_distinct(map_values) &*&
               true == ghostmap_distinct(map_addrs) &*&
               switch(key_optsh) {
                 case none: return map_values == map_values_rest &*& map_addrs == map_addrs_rest;
                 case some(kohv): return map_values_rest == ghostmap_remove(map_values, kohv) &*&
                                         map_addrs_rest == ghostmap_remove(map_addrs, kohv) &*&
                                         some(valuesh) == ghostmap_get(map_values, kohv) &*&
                                         some(kaddrsh) == ghostmap_get(map_addrs, kohv);
               };
    };

  // Keys + busybits + hashes + values => key options + map values + map addresses
  predicate mapp_core(size_t key_size, size_t capacity,
                      list<void*> kaddrs, list<bool> busybits, list<hash_t> hashes, list<void*> values,
                      list<option<list<char> > > key_opts, list<pair<list<char>, void*> > map_values, list<pair<list<char>, void*> > map_addrs) =
     key_opt_list(key_size, kaddrs, busybits, key_opts) &*&
     map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs) &*&
     hash_list(key_opts, hashes) &*&
     true == opt_no_dups(key_opts) &*&
     true == ghostmap_distinct(map_values) &*&
     true == ghostmap_distinct(map_addrs) &*&
     length(key_opts) == capacity &*&
     opts_size(key_opts) <= length(key_opts) &*&
     opts_size(key_opts) == length(map_values) &*&
     length(map_values) == length(map_addrs);

  // Map => its contents
  predicate mapp_raw(struct os_map* map; list<void*> kaddrs, list<bool> busybits, list<hash_t> hashes, list<size_t> chains, list<void*> values, size_t key_size, size_t capacity) =
    struct_os_map_padding(map) &*&
    map->kaddrs |-> ?kaddrs_ptr &*&
    map->busybits |-> ?busybits_ptr &*&
    map->hashes |-> ?hashes_ptr &*&
    map->chains |-> ?chains_ptr &*&
    map->values |-> ?values_ptr &*&
    map->key_size |-> key_size &*&
    map->capacity |-> capacity &*&
    kaddrs_ptr[0..capacity] |-> kaddrs &*&
    busybits_ptr[0..capacity] |-> busybits &*&
    hashes_ptr[0..capacity] |-> hashes &*&
    chains_ptr[0..capacity] |-> chains &*&
    values_ptr[0..capacity] |-> values;

  // Combine everything, including the chains optimization
  predicate mapp(struct os_map* map, size_t key_size, size_t capacity, list<pair<list<char>, void*> > map_values, list<pair<list<char>, void*> > map_addrs) =
    mapp_raw(map, ?kaddrs, ?busybits, ?hashes, ?chains, ?values, key_size, ?real_capacity) &*&
    mapp_core(key_size, real_capacity, kaddrs, busybits, hashes, values, ?key_opts, map_values, map_addrs) &*&
    buckets_keys_insync(real_capacity, chains, ?buckets, key_opts) &*&
    capacity == 0 ? real_capacity == 0
                  : (real_capacity >= capacity &*&
                     is_pow2(real_capacity, N63) != none);
@*/

static size_t get_real_capacity(size_t capacity)
//@ requires capacity <= (SIZE_MAX / 16);
/*@ ensures capacity == 0 ? result == 0 :
                            (result >= capacity &*&
                             result <= (SIZE_MAX / 8) &*&
                             is_pow2(result, N63) != none); @*/
{
  if (capacity == 0) {
    return 0;
  }
  size_t real_capacity = 1;
  while (real_capacity < capacity)
  /*@ invariant is_pow2(real_capacity, N63) != none; @*/;
  {
    real_capacity *= 2;
  }
  //@ assert none != is_pow2(real_capacity, N63);
  return real_capacity;
}

static size_t loop(size_t pos, size_t capacity)
//@ requires capacity == 0 || is_pow2(capacity, N63) != none;
//@ ensures capacity == 0 ? true : (0 <= result &*& result < capacity &*& result == loop_fp(pos, capacity));
{
  /*@ if (capacity != 0) {
        nat m = is_pow2_some(capacity, N63);
        mod_bitand_equiv(pos, capacity, m);
        div_mod_gt_0(pos % capacity, pos, capacity);
      } @*/
  // VeriFast checks for overflow even on unsigned variables, for which overflow is defined... this avoids an error
  //@ if (capacity == 0) assume(capacity-1 == SIZE_MAX);
  return pos & (capacity - 1);
}

/*@
lemma void move_chain(size_t* data, size_t i, size_t len)
  requires data[0..i] |-> ?l1 &*&
           data[i..len] |-> ?l2 &*&
           l2 == cons(?l2h, ?l2t) &*&
           i < len;
  ensures data[0..(i + 1)] |-> append(l1, cons(l2h, nil)) &*&
          data[(i + 1)..len] |-> tail(l2);
{
  open PRED_sizes(data, i, l1);
  switch(l1) {
    case nil:
      open PRED_sizes(data, len-i, l2);
      close PRED_sizes(data, 1, cons(l2h, nil));
    case cons(h, t):
      move_chain(data+1, i-1, len-1);
  }
  close PRED_sizes(data, i+1, append(l1, cons(l2h, nil)));
}

// ---

lemma void move_busybit(bool* data, size_t i, size_t len)
  requires data[0..i] |-> ?l1 &*&
           data[i..len] |-> ?l2 &*&
           l2 == cons(?l2h, ?l2t) &*&
           i < len;
  ensures data[0..(i + 1)] |-> append(l1, cons(l2h, nil)) &*&
          data[(i + 1)..len] |-> tail(l2);
{
  open bools(data, i, l1);
  switch(l1) {
    case nil:
      open bools(data, len-i, l2);
      close bools(data, 1, cons(l2h, nil));
    case cons(h, t):
      move_busybit(data+1, i-1, len-1);
  }
  close bools(data, i+1, append(l1, cons(l2h, nil)));
}

// ---

lemma void extend_repeat_n<t>(nat len, t extra, t z)
  requires true;
  ensures update(int_of_nat(len), z, append(repeat_n(len, z), cons(extra, nil))) == repeat_n(succ(len), z);
{
  switch(len) {
    case zero:
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
  assert 0 < length(cons(h,t));
  switch(nat_of_int(length(cons(h,t)))) {
    case zero:
      note(int_of_nat(zero) == length(cons(h,t)));
      assert false;
    case succ(lll):
  }
}

lemma void produce_key_opt_list(size_t key_size, list<hash_t> hashes, list<void*> kaddrs)
  requires length(hashes) == length(kaddrs);
  ensures key_opt_list(key_size, kaddrs, repeat_n(nat_of_int(length(kaddrs)), false), repeat_n(nat_of_int(length(kaddrs)), none)) &*&
          length(kaddrs) == length(repeat_n(nat_of_int(length(kaddrs)), none));
{
  switch(kaddrs) {
    case nil:
      close key_opt_list(key_size, kaddrs, repeat_n(nat_of_int(length(kaddrs)), false), repeat_n(nat_of_int(length(kaddrs)), none));
    case cons(kaddrh,kaddrt):
      switch(hashes) {
        case nil:
        case cons(hh,ht):
      }
      produce_key_opt_list(key_size, tail(hashes), kaddrt);
      nat_len_of_non_nil(kaddrh,kaddrt);
      close key_opt_list(key_size, kaddrs, repeat_n(nat_of_int(length(kaddrs)), false), repeat_n(nat_of_int(length(kaddrs)), none));
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

lemma void produce_empty_hash_list(list<option<list<char> > > key_opts, list<hash_t> hashes)
  requires length(key_opts) == length(hashes) &*&
           key_opts == repeat_n(nat_of_int(length(hashes)), none);
  ensures hash_list(key_opts, hashes);
{
  switch(hashes) {
    case nil:
      close hash_list(nil, nil);
    case cons(h, t):
      assert key_opts == cons(?koh, ?kot);
      repeat_n_is_n(nat_of_int(length(hashes)), none);
      nat_len_of_non_nil(h,t);
      produce_empty_hash_list(kot, t);
      close hash_list(repeat_n(nat_of_int(length(hashes)), none), hashes);
  }
}

// ---

lemma void empty_keychains_start_on_hash(nat len, size_t pos, size_t capacity)
  requires true;
  ensures true == key_chains_start_on_hash_fp(empty_buckets_fp<list<char> >(len), pos, capacity);
{
  switch(len) {
    case zero:
    case succ(n):
      empty_keychains_start_on_hash(n, pos + 1, capacity);
  }
}

lemma void empty_buckets_insync(list<size_t> chains, size_t capacity)
  requires capacity >= 0 &*& // bug in VeriFast, this should be trivially true
           chains == repeat_n(nat_of_int(capacity), 0);
  ensures buckets_keys_insync(capacity, chains,
                              empty_buckets_fp<list<char> >(nat_of_int(capacity)),
                              repeat_n(nat_of_int(capacity), none));
{
  empty_buckets_chns_zeros<list<char> >(nat_of_int(capacity));
  empty_buckets_ok<list<char> >(nat_of_int(capacity));
  empty_buckets_ks_none<list<char> >(nat_of_int(capacity));
  empty_keychains_start_on_hash(nat_of_int(capacity), 0, capacity);
  repeat_n_length(nat_of_int(capacity), bucket(nil));
  int_of_nat_of_int(capacity);
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

lemma void produce_empty_map_valuesaddrs(size_t capacity, list<void*> kaddrs, list<void*> values)
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
      produce_empty_map_valuesaddrs(capacity - 1, kt, vt);
      repeat_n_tail(nat_of_int(capacity), none);
      assert not == repeat_n(nat_of_int(capacity-1), none);
      assert true == distinct(nil);
      close map_valuesaddrs(kaddrs, repeat_n(nat_of_int(capacity), none), values, nil, nil);
  }
}
@*/

struct os_map* os_map_alloc(size_t key_size, size_t capacity)
/*@ requires capacity <= (SIZE_MAX / 16); @*/
/*@ ensures mapp(result, key_size, capacity, nil, nil); @*/
{
  size_t real_capacity = get_real_capacity(capacity);
  struct os_map* map = (struct os_map*) os_memory_alloc(1, sizeof(struct os_map));
  //@ close_struct_zero(map);
  void** kaddrs = (void**) os_memory_alloc(real_capacity, sizeof(void*));
  bool* busybits = (bool*) os_memory_alloc(real_capacity, sizeof(bool));
  hash_t* hashes = (hash_t*) os_memory_alloc(real_capacity, sizeof(hash_t));
  size_t* chains = (size_t*) os_memory_alloc(real_capacity, sizeof(size_t));
  void** values = (void**) os_memory_alloc(real_capacity, sizeof(void*));

  //@ assert chains[0..real_capacity] |-> ?chains_lst;
  //@ assert busybits[0..real_capacity] |-> ?busybits_lst;
  size_t i = 0;
  for (; i < real_capacity; ++i)
    /*@ invariant busybits[0..i] |-> repeat_n(nat_of_int(i), false) &*&
                  busybits[i..real_capacity] |-> ?busybits_rest &*&
                  chains[0..i] |-> repeat_n(nat_of_int(i), 0) &*&
                  chains[i..real_capacity] |-> ?chains_rest &*&
                  0 <= i &*& i <= real_capacity; @*/
    //@ decreases real_capacity - i;
  {
    //@ move_busybit(busybits, i, real_capacity);
    //@ move_chain(chains, i, real_capacity);
    //@ assert busybits_rest == cons(?bbrh, _);
    //@ assert chains_rest == cons(?crh, _);
    //@ extend_repeat_n(nat_of_int(i), bbrh, false);
    //@ extend_repeat_n(nat_of_int(i), crh, 0);
    busybits[i] = false;
    chains[i] = 0;
    //@ assert succ(nat_of_int(i)) == nat_of_int(i+1);
  }
  //@ assert kaddrs[0..real_capacity] |-> ?kaddrs_lst;
  //@ chars_to_hashes(hashes, real_capacity);
  //@ assert hashes[0..real_capacity] |-> ?hashes_lst;
  //@ assert values[0..real_capacity] |-> ?values_lst;
  //@ produce_key_opt_list(key_size, hashes_lst, kaddrs_lst);
  //@ assert key_opt_list(key_size, kaddrs_lst, _, ?kopts);
  //@ repeat_n_contents(nat_of_int(real_capacity), none);
  //@ kopts_size_0_when_empty(kopts);

  map->kaddrs = kaddrs;
  map->busybits = busybits;
  map->hashes = hashes;
  map->chains = chains;
  map->values = values;
  map->capacity = real_capacity;
  map->key_size = key_size;

  //@ close mapp_raw(map, kaddrs_lst, ?zeroed_busybits_lst, hashes_lst, ?zeroed_chains_lst, values_lst, key_size, real_capacity);
  //@ empty_buckets_insync(zeroed_chains_lst, real_capacity);
  //@ produce_empty_map_valuesaddrs(real_capacity, kaddrs_lst, values_lst);
  //@ produce_empty_hash_list(kopts, hashes_lst);
  //@ repeat_none_is_opt_no_dups(nat_of_int(real_capacity), kopts);
  //@ close mapp_core(key_size, real_capacity, kaddrs_lst, zeroed_busybits_lst, hashes_lst, values_lst, kopts, nil, nil);
  //@ close mapp(map, key_size, capacity, nil, nil);
  return map;
}


/*@
lemma list<char> extract_key_at_index(list<void*> kaddrs_b, list<bool> busybits_b, list<option<list<char> > > key_opts_b, size_t n, 
                                      list<bool> busybits, list<option<list<char> > > key_opts)
  requires key_opt_list(?key_size, ?kaddrs, busybits, key_opts) &*&
           key_opt_list(key_size, kaddrs_b, busybits_b, key_opts_b) &*&
           0 <= n &*& n < length(busybits) &*& true == nth(n, busybits);
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
      return nil;
    case cons(bbh, bbt):
      switch(kaddrs) {
        case nil: return nil;
        case cons(kph, kpt):
          switch(key_opts) {
            case nil: return nil;
            case cons(kh, kt):
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

lemma void reconstruct_key_opt_list(list<void*> kaddrs1, list<bool> busybits1, 
                                    list<void*> kaddrs2, list<bool> busybits2)
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
    case cons(bbh, bbt):
      append_reverse_tail_cons_head(kaddrs1, kaddrs2);
      append_reverse_tail_cons_head(busybits1, busybits2);
      append_reverse_tail_cons_head(key_opts1, key_opts2);
      assert kaddrs1 == cons(?ka1h, ?ka1t);
      assert key_opts1 == cons(?ko1h, _);
      close key_opt_list(key_size, cons(ka1h, kaddrs2), cons(bbh, busybits2), cons(ko1h, key_opts2));
      reconstruct_key_opt_list(ka1t, bbt, cons(ka1h, kaddrs2), cons(bbh, busybits2));
  }
}

lemma void recover_key_opt_list(list<void*> kaddrs, list<bool> busybits, list<option<list<char> > > key_opts, size_t n)
  requires key_opt_list(?key_size, reverse(take(n, kaddrs)), reverse(take(n, busybits)), reverse(take(n, key_opts))) &*&
           true == nth(n, busybits) &*&
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

lemma void key_opt_list_find_key(list<option<list<char> > > key_opts, size_t i, list<char> k)
  requires nth(i, key_opts) == some(k) &*&
           true == opt_no_dups(key_opts) &*&
           0 <= i &*& i < length(key_opts);
  ensures index_of(some(k), key_opts) == i;
{
  switch(key_opts) {
    case nil:
    case cons(h,t):
      if (h == some(k)) {
        assert i == 0;
      } else {
        key_opt_list_find_key(t, i-1, k);
      }
  }
}

// ---

lemma void no_hash_no_key(list<option<list<char> > > key_opts, list<hash_t> hashes, list<char> k, size_t i)
  requires hash_list(key_opts, hashes) &*&
           nth(i, hashes) != hash_fp(k) &*&
           0 <= i &*& i < length(key_opts);
  ensures hash_list(key_opts, hashes) &*&
          nth(i, key_opts) != some(k);
{
  open hash_list(key_opts, hashes);
  switch(key_opts) {
    case nil:
      assert hashes == nil;
    case cons(kh,kt):
      assert hashes == cons(?hh, ?ht);
      if (i == 0) {
        assert nth(i, key_opts) == kh;
        if (kh == some(k)) {
          assert hh == hash_fp(k);
          nth_0_head(hashes);
          assert nth(i, hashes) == hh;
          assert nth(i, hashes) == hash_fp(k);
        }
      } else {
        nth_cons(i, ht, hh);
        cons_head_tail(hashes);
        assert nth(i, hashes) == nth(i-1, ht);
        no_hash_no_key(kt, ht, k, i-1);
      }
  }
  close hash_list(key_opts, hashes);
}

// ---

lemma void no_bb_no_key(list<option<list<char> > > key_opts, list<bool> busybits, size_t i)
  requires key_opt_list(?key_size, ?kaddrs, busybits, key_opts) &*& 0 <= i &*& i < length(key_opts) &*&
           false == nth(i, busybits);
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
                              size_t shift, size_t capacity,
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

lemma void overshoot_bucket(list<bucket<list<char> > > buckets, size_t shift, size_t capacity, list<char> k)
  requires true == key_chains_start_on_hash_fp(buckets, shift, capacity) &*&
           loop_fp(hash_fp(k), capacity) < shift &*& shift <= capacity &*&
           capacity - shift == length(buckets);
  ensures false == exists(buckets, (bucket_has_key_fp)(k));
{
  switch(buckets) {
    case nil:
    case cons(bh,bt):
      switch(bh) { case bucket(chains):
        if (bucket_has_key_fp(k, bh)) {
            assert true == mem(k, map(fst, chains));
            assert true == forall(chains, (has_given_hash)(shift, capacity));
            hash_for_given_key(chains, shift, capacity, k);
        }
        overshoot_bucket(bt, shift + 1, capacity, k);
      }
  }
}

// ---

lemma void no_hash_not_in_this_bucket(list<pair<list<char>, nat> > chains, list<char> k,
                                      size_t shift, size_t capacity)
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
                             size_t shift, size_t capacity)
  requires true == key_chains_start_on_hash_fp(cons(bh,bt), shift, capacity) &*&
           shift != loop_fp(hash_fp(k), capacity);
  ensures false == bucket_has_key_fp(k, bh);
{
  switch(bh) { case bucket(chains):
    no_hash_not_in_this_bucket(chains, k, shift, capacity);
  }
}

lemma void key_is_contained_in_the_bucket_rec(list<bucket<list<char> > > buckets, list<pair<list<char>, nat> > acc,
                                              size_t shift, size_t capacity,
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
    case nil:
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
                                       size_t start, size_t capacity)
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
                                          size_t capacity, list<char> k)
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

lemma void chains_depleted_no_hope(list<bucket<list<char> > > buckets, size_t i,
                                   size_t start, list<char> k, size_t capacity)
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
  }
}

lemma void map_values_reflects_keyopts_mem<k,v>(list<char> key, size_t idx)
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

bool os_map_get(struct os_map* map, void* key_ptr, void** out_value)
/*@ requires mapp(map, ?key_size, ?capacity, ?map_values, ?map_addrs) &*&
             [?frac]chars(key_ptr, key_size, ?key) &*&
             *out_value |-> _; @*/
/*@ ensures mapp(map, key_size, capacity, map_values, map_addrs) &*&
            [frac]chars(key_ptr, key_size, key) &*&
            switch(ghostmap_get(map_values, key)) {
              case none: return result == false &*& *out_value |-> _;
              case some(v): return result == true &*& *out_value |-> v;
            }; @*/
{
  //@ open mapp(map, key_size, capacity, map_values, map_addrs);
  hash_t key_hash = generic_hash(key_ptr, map->key_size);
  size_t start = loop(key_hash, map->capacity);
  for (size_t i = 0; i < map->capacity; ++i)
    /*@ invariant mapp_raw(map, ?kaddrs_lst, ?busybits_lst, ?hashes_lst, ?chains_lst, ?values_lst, key_size, ?real_capacity) &*&
                  mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, ?key_opts, map_values, map_addrs) &*&
                  buckets_keys_insync(real_capacity, chains_lst, ?buckets, key_opts) &*&
                  0 <= i &*& i <= real_capacity &*&
                  [frac]chars(key_ptr, key_size, key) &*&
                  hash_fp(key) == key_hash &*&
                  capacity == 0 ? real_capacity == 0 :
                                  (real_capacity >= capacity &*&
                                   start < real_capacity &*&
                                   start == loop_fp(hash_fp(key), real_capacity) &*&
                                   is_pow2(real_capacity, N63) != none) &*&
                  true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, start)) &*&
                  *out_value |-> _;
    @*/
    //@ decreases real_capacity - i;
  {
    //@ open mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
    //@ open buckets_keys_insync(real_capacity, chains_lst, buckets, key_opts);
    size_t index = loop(start + i, map->capacity);
    void* kp = map->kaddrs[index];
    bool bb = map->busybits[index];
    hash_t kh = map->hashes[index];
    size_t chn = map->chains[index];
    if (bb && kh == key_hash) {
      //@ close key_opt_list(key_size, nil, nil, nil);
      //@ extract_key_at_index(nil, nil, nil, index, busybits_lst, key_opts);
      //@ append_nil(reverse(take(index, kaddrs_lst)));
      //@ append_nil(reverse(take(index, busybits_lst)));
      //@ append_nil(reverse(take(index, key_opts)));
      if (generic_eq(kp, key_ptr, map->key_size)) {
        //@ recover_key_opt_list(kaddrs_lst, busybits_lst, key_opts, index);
        //@ open map_valuesaddrs(kaddrs_lst, key_opts, values_lst, map_values, map_addrs);
        //@ assert true == opt_no_dups(key_opts);
        //@ close map_valuesaddrs(kaddrs_lst, key_opts, values_lst, map_values, map_addrs);
        //@ key_opt_list_find_key(key_opts, index, key);
        //@ close buckets_keys_insync(real_capacity, chains_lst, buckets, key_opts);
        //@ map_values_reflects_keyopts_mem(key, index);
        *out_value = map->values[index];
        //@ close mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
        //@ close mapp_raw(map, kaddrs_lst, busybits_lst, hashes_lst, chains_lst, values_lst, key_size, real_capacity);
        //@ close mapp(map, key_size, capacity, map_values, map_addrs);
        return true;
      }
      //@ recover_key_opt_list(kaddrs_lst, busybits_lst, key_opts, index);
    } else {
      //@ if (bb) no_hash_no_key(key_opts, hashes_lst, key, index); else no_bb_no_key(key_opts, busybits_lst, index);
      if (chn == 0) {
        //@ assert length(chains_lst) == real_capacity;
        //@ buckets_keys_chns_same_len(buckets);
        //@ assert length(buckets) == real_capacity;
        //@ no_crossing_chains_here(buckets, index);
        //@ assert nil == get_crossing_chains_fp(buckets, index);
        //@ key_is_contained_in_the_bucket(buckets, real_capacity, key);
        //@ assert true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, start));
        //@ assert true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, loop_fp(hash_fp(key), real_capacity)));
        //@ assert true == up_to(succ(nat_of_int(i)), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, loop_fp(hash_fp(key), real_capacity)));
        //@ assert true == up_to(nat_of_int(i+1), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, loop_fp(hash_fp(key), real_capacity)));
        //@ assert buckets != nil;
        //@ chains_depleted_no_hope(buckets, i, loop_fp(hash_fp(key), real_capacity), key, real_capacity);
        //@ assert false == mem(some(key), key_opts);
        //@ key_opts_has_not_implies_map_values_has_not(key);
        //@ close buckets_keys_insync(real_capacity, chains_lst, buckets, key_opts);
        //@ close mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
        //@ close mapp_raw(map, kaddrs_lst, busybits_lst, hashes_lst, chains_lst, values_lst, key_size, real_capacity);
        //@ close mapp(map, key_size, capacity, map_values, map_addrs);
        return false;
      }
      //@ assert(length(key_opts) == real_capacity);
    }
    //@ assert(nth(index, key_opts) != some(key));
    //@ assert(true == neq(some(key), nth(index, key_opts)));
    //@ assert(true == neq(some(key), nth(loop_fp(i+start, real_capacity), key_opts)));
    //@ assert(nat_of_int(i+1) == succ(nat_of_int(i)));
    //@ close buckets_keys_insync(real_capacity, chains_lst, buckets, key_opts);
    //@ close mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
  }
  //@ open mapp_core(key_size, ?real_capacity, ?kaddrs_lst, ?busybits_lst, ?hashes_lst, ?values_lst, ?key_opts, map_values, map_addrs);
  //@ assert buckets_keys_insync(real_capacity, ?chains_lst, ?buckets, key_opts);
  //@ if (real_capacity != 0) by_loop_for_all(key_opts, (neq)(some(key)), start, real_capacity, nat_of_int(real_capacity));
  //@ no_key_found(key_opts, key);
  //@ key_opts_has_not_implies_map_values_has_not(key);
  //@ close mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
  //@ close mapp(map, key_size, capacity, map_values, map_addrs);
  return false;
}


/*@
fixpoint bool cell_busy(option<list<char> > x) { return x != none; }

lemma void full_size(list<option<list<char> > > key_opts)
  requires true == up_to(nat_of_int(length(key_opts)), (nthProp)(key_opts, cell_busy));
  ensures opts_size(key_opts) == length(key_opts);
{
  switch(key_opts) {
    case nil:
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
    case nil:
    case cons(h,t):
      key_opts_size_limits(t);
  }
}

lemma void zero_bbs_is_for_empty(list<bool> busybits, list<option<list<char> > > key_opts, size_t i)
  requires key_opt_list(?key_size, ?kaddrs, busybits,  key_opts) &*&
           false == nth(i, busybits) &*&
           0 <= i &*& i < length(busybits);
  ensures key_opt_list(key_size, kaddrs, busybits, key_opts) &*&
          nth(i, key_opts) == none &*&
          opts_size(key_opts) < length(key_opts);
{
  open key_opt_list(key_size, kaddrs, busybits, key_opts);
  switch(busybits) {
    case nil:
    case cons(h,t):
      if (i == 0) {
        key_opts_size_limits(tail(key_opts));
      } else {
        nth_cons(i, t, h);
        zero_bbs_is_for_empty(t, tail(key_opts), i-1);
      }
  }
  close key_opt_list(key_size, kaddrs, busybits, key_opts);
}

// ---

lemma void start_Xchain(size_t capacity, list<hash_t> chains,  list<bucket<list<char> > > buckets, list<option<list<char> > > key_opts, size_t start)
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

lemma void bb_nonzero_cell_busy(list<bool> busybits, list<option<list<char> > > key_opts, size_t i)
  requires key_opt_list(?key_size, ?kaddrs, busybits, key_opts) &*&
           true == nth(i, busybits) &*&
           0 <= i &*& i < length(busybits);
  ensures key_opt_list(key_size, kaddrs, busybits, key_opts) &*&
          true == cell_busy(nth(i, key_opts));
  {
    open key_opt_list(key_size, kaddrs, busybits, key_opts);
    switch(busybits) {
      case nil:
      case cons(h,t):
      if (i == 0) {
      } else {
        nth_cons(i, t, h);
        bb_nonzero_cell_busy(t, tail(key_opts), i-1);
      }
    }
    close key_opt_list(key_size, kaddrs, busybits, key_opts);
  }

// ---

lemma void put_keeps_key_opt_list(list<void*> kaddrs, list<bool> busybits, list<option<list<char> > > key_opts, int index, void* key, list<char> k)
  requires key_opt_list(?key_size, kaddrs, busybits, key_opts) &*&
           [0.25]chars(key, key_size, k) &*&
           0 <= index &*& index < length(busybits) &*&
           nth(index, key_opts) == none;
  ensures key_opt_list(key_size, update(index, key, kaddrs), update(index, true, busybits), update(index, some(k), key_opts));
{
  open key_opt_list(key_size, kaddrs, busybits, key_opts);
  switch(busybits) {
    case nil:
    case cons(bbh, bbt):
      assert kaddrs == cons(?kah, ?kat);
      assert key_opts == cons(?koh, ?kot);
      if (index == 0) {
        tail_of_update_0(kaddrs, key);
        tail_of_update_0(key_opts, some(k));
        head_update_0(key, kaddrs);
      } else {
        put_keeps_key_opt_list(kat, bbt, kot, index-1, key, k);
        cons_head_tail(kaddrs);
        cons_head_tail(key_opts);
        update_tail_tail_update(kah, kat, index, key);
        update_tail_tail_update(koh, kot, index, some(k));
        update_tail_tail_update(bbh, bbt, index, true);
      }
      update_non_nil(kaddrs, index, key);
      update_non_nil(key_opts, index, some(k));
  }
  close key_opt_list(key_size, update(index, key, kaddrs), update(index, true, busybits), update(index, some(k), key_opts));
}

// ---

lemma void map_values_has_not_implies_key_opts_has_not(list<pair<list<char>, void*> > map_values, list<option<list<char> > > key_opts, list<char> key)
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
          ghostmap_remove_preserves_other(map_values, kohv, key);
          map_values_has_not_implies_key_opts_has_not(map_values_rest, key_optst, key);
          close map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
      }
  }
}

// ---

lemma void buckets_put_chains_still_start_on_hash(list<bucket<list<char> > > buckets, list<char> k, size_t shift,
                                                  size_t start, size_t dist, size_t capacity)
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

lemma void buckets_keys_put_key_insync(size_t capacity, list<size_t> chains, size_t start,
                                       size_t fin, list<char> k, list<option<list<char> > > key_opts)
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

lemma void put_preserves_no_dups(list<option<list<char> > > key_opts, size_t i, list<char> k)
  requires false == mem(some(k), key_opts) &*& 
           true == opt_no_dups(key_opts);
  ensures true == opt_no_dups(update(i, some(k), key_opts));
{
  switch(key_opts) {
    case nil:
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

lemma void put_updates_valuesaddrs(size_t index, void* key_ptr, list<char> key, void* value)
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
  switch(key_opts) {
    case nil:
    case cons(key_optsh, key_optst):
      open map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
      if (index == 0) {
        ghostmap_remove_cancels_set(map_values, key, value);
        ghostmap_remove_cancels_set(map_addrs, key, key_ptr);
      } else {
        switch(key_optsh) {
          case none:
          case some(kohv):
            ghostmap_remove_preserves_other(map_values, kohv, key);
            ghostmap_remove_preserves_other(map_addrs, kohv, key);
            ghostmap_set_remove_different_key_interchangeable(map_values, key, value, kohv);
            ghostmap_set_remove_different_key_interchangeable(map_addrs, key, key_ptr, kohv);
            ghostmap_set_preserves_other(map_values, key, value, kohv);
            ghostmap_set_preserves_other(map_addrs, key, key_ptr, kohv);
        }
        put_updates_valuesaddrs(index - 1, key_ptr, key, value);
      }
      ghostmap_set_new_preserves_distinct(map_values, key, value);
      ghostmap_set_new_preserves_distinct(map_addrs, key, key_ptr);
      close map_valuesaddrs(update(index, key_ptr, kaddrs),
                            update(index, some(key), key_opts),
                            update(index, value, values),
                            ghostmap_set(map_values, key, value),
                            ghostmap_set(map_addrs, key, key_ptr));
  }
}

// ---

lemma void put_preserves_hash_list(list<option<list<char> > > key_opts, list<hash_t> hashes, size_t index, list<char> k, hash_t hash)
  requires hash_list(key_opts, hashes) &*&
           hash_fp(k) == hash &*&
           0 <= index;
  ensures hash_list(update(index, some(k), key_opts), update(index, hash, hashes));
{
  open hash_list(key_opts, hashes);
  switch(key_opts) {
    case nil:
    case cons(koh, kot):
      if (index != 0) {
        assert hashes == cons(?hh, ?ht);
        put_preserves_hash_list(kot, ht, index - 1, k, hash);
      }
  }
  close hash_list(update(index, some(k), key_opts), update(index, hash, hashes));
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

void os_map_set(struct os_map* map, void* key_ptr, void* value)
/*@ requires mapp(map, ?key_size, ?capacity, ?map_values, ?map_addrs) &*&
             [0.25]chars(key_ptr, key_size, ?key) &*&
             length(map_values) < capacity &*&
             ghostmap_get(map_values, key) == none &*&
             ghostmap_get(map_addrs, key) == none; @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_set(map_values, key, value), ghostmap_set(map_addrs, key, key_ptr)); @*/
{
  //@ open mapp(map, key_size, capacity, map_values, map_addrs);
  hash_t hash = generic_hash(key_ptr, map->key_size);
  size_t start = loop(hash, map->capacity);
  //@ assert buckets_keys_insync(?real_capacity, ?old_chains_lst, ?buckets, ?key_opts);
  //@ start_Xchain(real_capacity, old_chains_lst, buckets, key_opts, start);
  //@ loop_bijection(start, real_capacity);
  for (size_t i = 0; i < map->capacity; ++i)
    /*@ invariant mapp_raw(map, ?kaddrs_lst, ?busybits_lst, ?hashes_lst, ?chains_lst, ?values_lst, key_size, real_capacity) &*&
                  mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs) &*&
                  is_pow2(real_capacity, N63) != none &*&
                  [0.25]chars(key_ptr, key_size, key) &*&
                  0 <= i &*& i <= real_capacity &*&
                  true == up_to(nat_of_int(i),(byLoopNthProp)(key_opts, cell_busy, real_capacity, start)) &*&
                  buckets_keys_insync_Xchain(real_capacity, chains_lst, buckets, start, loop_fp(start + i, real_capacity), key_opts);
      @*/
    //@ decreases real_capacity - i;
  {
    size_t index = loop(start + i, map->capacity);
    //@ open mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
    //@ open buckets_keys_insync_Xchain(real_capacity, chains_lst, buckets, start, index, key_opts);
    bool bb = map->busybits[index];
    if (!bb) {
      //@ zero_bbs_is_for_empty(busybits_lst, key_opts, index);
      //@ map_values_has_not_implies_key_opts_has_not(map_values, key_opts, key);
      map->kaddrs[index] = key_ptr;
      map->busybits[index] = true;
      map->hashes[index] = hash;
      map->values[index] = value;
      //@ no_key_in_ks_no_key_in_buckets(buckets, key);
      //@ close buckets_keys_insync_Xchain(real_capacity, chains_lst, buckets, start, index, key_opts);
      //@ buckets_keys_put_key_insync(real_capacity, chains_lst, start, index, key, key_opts);
      //@ put_keeps_key_opt_list(kaddrs_lst, busybits_lst, key_opts, index, key_ptr, key);
      //@ put_updates_valuesaddrs(index, key_ptr, key, value);
      //@ put_preserves_no_dups(key_opts, index, key);
      //@ put_preserves_hash_list(key_opts, hashes_lst, index, key, hash);
      //@ put_increases_key_opts_size(key_opts, index, key);
      //@ ghostmap_set_new_preserves_distinct(map_values, key, value);
      //@ ghostmap_set_new_preserves_distinct(map_addrs, key, key_ptr);
      //@ assert true == ghostmap_distinct(ghostmap_set(map_values, key, value));
      //@ close mapp_core(key_size, real_capacity, ?new_kaddrs_lst, ?new_busybits_lst, ?new_hashes_lst, ?new_values_lst, ?new_key_opts, ?new_map_values, ?new_map_addrs);
      //@ close mapp(map, key_size, capacity, new_map_values, new_map_addrs);
      return;
    }
    size_t chn = map->chains[index];
    //@ buckets_keys_chns_same_len(buckets);
    //@ buckets_ok_chn_bound(buckets, index);
    //@ outside_part_chn_no_effect(buckets_get_chns_fp(buckets), start, index, real_capacity);
    //@ assert chn <= real_capacity;
    map->chains[index] = chn + 1;
    //@ bb_nonzero_cell_busy(busybits_lst, key_opts, index);
    //@ assert true == cell_busy(nth(loop_fp(i+start, real_capacity), key_opts));
    //@ assert nat_of_int(i+1) == succ(nat_of_int(i));
    //@ Xchain_add_one(chains_lst, buckets_get_chns_fp(buckets), start, index < start ? real_capacity + index - start : index - start, real_capacity);
    /*@
        if (i + 1 == real_capacity) {
          by_loop_for_all(key_opts, cell_busy, start, real_capacity, nat_of_int(real_capacity));
          full_size(key_opts);
          assert false;
        }
    @*/
    /*@
        if (index < start) {
          if (start + i < real_capacity) loop_bijection(start + i, real_capacity);
          loop_injection_n(start + i + 1 - real_capacity, real_capacity, 1);
          loop_bijection(start + i + 1 - real_capacity, real_capacity);
          loop_injection_n(start + i - real_capacity, real_capacity, 1);
          loop_bijection(start + i - real_capacity, real_capacity);
        } else {
          if (real_capacity <= start + i) {
            loop_injection_n(start + i - real_capacity, real_capacity, 1);
            loop_bijection(start + i - real_capacity, real_capacity);
          }
          loop_bijection(start + i, real_capacity);
          if (start + i + 1 == real_capacity) {
            loop_injection_n(start + i + 1 - real_capacity, real_capacity, 1);
            loop_bijection(start + i + 1 - real_capacity, real_capacity);
          } else {
            loop_bijection(start + i + 1, real_capacity);
          }
        }
      @*/
    //@ close buckets_keys_insync_Xchain(real_capacity, ?new_chains_lst, buckets, start, index, key_opts);
    //@ close mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
  }
  //@ open mapp_core(key_size, real_capacity, ?kaddrs_lst, ?busybits_lst, ?hashes_lst, ?values_lst, key_opts, map_values, map_addrs);
  //@ by_loop_for_all(key_opts, cell_busy, start, real_capacity, nat_of_int(real_capacity));
  //@ full_size(key_opts);
  //@ assert false;
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

lemma void key_opts_rem_preserves_hash_list(list<option<list<char> > > key_opts, list<hash_t> hashes, size_t index)
requires hash_list(key_opts, hashes) &*& 0 <= index;
ensures hash_list(update(index, none, key_opts), hashes);
{
  open hash_list(key_opts, hashes);
  switch(key_opts) {
    case nil:
    case cons(h, t):
      if (index != 0) {
        key_opts_rem_preserves_hash_list(t, tail(hashes), index - 1);
      }
  }
  close hash_list(update(index, none, key_opts), hashes);
}

// ---

lemma void map_drop_key(size_t index)
requires key_opt_list(?key_size, ?kaddrs, ?busybits, ?key_opts) &*&
         map_valuesaddrs(kaddrs, key_opts, ?values, ?map_values, ?map_addrs) &*&
         0 <= index &*& index < length(key_opts) &*&
         nth(index, key_opts) == some(?key) &*&
         ghostmap_get(map_values, key) != none &*&
         ghostmap_get(map_addrs, key) == some(?key_ptr) &*&
         true == opt_no_dups(key_opts) &*&
         true == ghostmap_distinct(map_values) &*&
         true == ghostmap_distinct(map_addrs);
ensures key_opt_list(key_size, kaddrs, update(index, false, busybits), update(index, none, key_opts)) &*&
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
      ghostmap_remove_when_distinct_and_present_decreases_length(map_values, key);
      ghostmap_remove_when_distinct_and_present_decreases_length(map_addrs, key);
      if (index == 0) {
        assert busybits == cons(?busybitsh, ?busybitst);
        close map_valuesaddrs(kaddrs, cons(none, key_optst), values, map_values_rest, map_addrs_rest);
        close key_opt_list(key_size, kaddrs, cons(false, busybitst), cons(none, key_optst));
      } else {
        switch(key_optsh) {
          case none:
            map_drop_key(index - 1);
            assert map_valuesaddrs(kaddrst, update(index - 1, none, key_optst), valuest, ?new_map_values, ?new_map_addrs);
            close map_valuesaddrs(kaddrs, update(index, none, key_opts), values, new_map_values, new_map_addrs);
            close key_opt_list(key_size, kaddrs, update(index, false, busybits), update(index, none, key_opts));
          case some(kohv):
            ghostmap_remove_preserves_other(map_values, kohv, key);
            ghostmap_remove_preserves_other(map_addrs, kohv, key);
            map_drop_key(index - 1);
            ghostmap_remove_order_is_irrelevant(map_values, key, kohv);
            ghostmap_remove_order_is_irrelevant(map_addrs, key, kohv);
            ghostmap_remove_preserves_other(map_values, key, kohv);
            ghostmap_remove_preserves_other(map_addrs, key, kohv);
            close map_valuesaddrs(kaddrs, update(index, none, key_opts), values, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key));
            close key_opt_list(key_size, kaddrs, update(index, false, busybits), update(index, none, key_opts));
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

// ---

lemma void opts_size_at_least_0(list<option<list<char> > > key_opts)
requires true;
ensures opts_size(key_opts) >= 0;
{
  switch(key_opts) {
    case nil:
    case cons(h, t):
      opts_size_at_least_0(t);
  }
}

lemma void key_opts_has_implies_not_empty(list<option<list<char> > > key_opts, list<char> key)
requires true == mem(some(key), key_opts);
ensures opts_size(key_opts) >= 1;
{
  switch(key_opts) {
    case nil:
      assert false;
    case cons(h, t):
      if (h == some(key)) {
        opts_size_at_least_0(t);
      } else {
        key_opts_has_implies_not_empty(t, key);
      }
  }
}

@*/

void os_map_remove(struct os_map* map, void* key_ptr)
/*@ requires mapp(map, ?key_size, ?capacity, ?map_values, ?map_addrs) &*&
             [?frac]chars(key_ptr, key_size, ?key) &*&
             frac != 0.0 &*&
             ghostmap_get(map_values, key) != none &*&
             ghostmap_get(map_addrs, key) == some(key_ptr); @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key)) &*&
           [frac + 0.25]chars(key_ptr, key_size, key); @*/
{
  //@ open mapp(map, key_size, capacity, map_values, map_addrs);
  hash_t key_hash = generic_hash(key_ptr, map->key_size);
  //@ open mapp_core(key_size, ?real_capacity, ?kaddrs_lst, ?busybits_lst, ?hashes_lst, ?values_lst, ?key_opts, map_values, map_addrs);
  //@ map_values_has_implies_key_opts_has(key);
  //@ key_opts_has_implies_not_empty(key_opts, key);
  //@ close mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
  size_t start = loop(key_hash, map->capacity);
  //@ open buckets_keys_insync(real_capacity, ?old_chains_lst, ?buckets, key_opts);
  //@ buckets_keys_chns_same_len(buckets);
  //@ key_is_contained_in_the_bucket(buckets, real_capacity, key);
  //@ buckets_remove_add_one_chain(buckets, start, key);
  //@ loop_bijection(start, real_capacity);
  for (size_t i = 0; i < map->capacity; ++i)
    /*@ invariant mapp_raw(map, kaddrs_lst, busybits_lst, hashes_lst, ?chains_lst, values_lst, key_size, real_capacity) &*&
                  mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs) &*&
                  is_pow2(real_capacity, N63) != none &*&
                  0 <= i &*& i <= real_capacity &*&
                  [frac]chars(key_ptr, key_size, key) &*&
                  hash_fp(key) == key_hash &*&
                  key_opts == buckets_get_keys_fp(buckets) &*&
                  i <= buckets_get_chain_fp(buckets, key, start) &*&
                  chains_lst == add_partial_chain_fp(loop_fp(start + i, real_capacity), 
                                                     buckets_get_chain_fp(buckets, key, start) - i, 
                                                     buckets_get_chns_fp(buckets_remove_key_fp(buckets, key))) &*&
                  true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, start)); @*/
    //@ decreases real_capacity - i;
  {
    //@ open mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
    size_t index = loop(start + i, map->capacity);
    bool bb = map->busybits[index];
    hash_t kh = map->hashes[index];
    size_t chn = map->chains[index];
    void* kp = map->kaddrs[index];
    if (bb && kh == key_hash) {
      //@ close key_opt_list(key_size, nil, nil, nil);
      //@ extract_key_at_index(nil, nil, nil, index, busybits_lst, key_opts);
      //@ append_nil(reverse(take(index, kaddrs_lst)));
      //@ append_nil(reverse(take(index, busybits_lst)));
      //@ append_nil(reverse(take(index, key_opts)));
      if (generic_eq(kp, key_ptr, map->key_size)) {
        //@ recover_key_opt_list(kaddrs_lst, busybits_lst, key_opts, index);
        //@ key_opt_list_find_key(key_opts, index, key);
        map->busybits[index] = false;
        //@ rem_preserves_opt_no_dups(key_opts, index);
        //@ key_opts_rem_preserves_hash_list(key_opts, hashes_lst, index);
        //@ remove_decreases_key_opts_size(key_opts, index);
        //@ map_drop_key(index);
        //@ ghostmap_remove_when_distinct_and_present_decreases_length(map_values, key);
        //@ ghostmap_remove_when_distinct_and_present_decreases_length(map_addrs, key);
        //@ chns_after_partial_chain_ended(buckets, key, start, i, real_capacity);
        //@ buckets_remove_key_still_ok(buckets, key);
        //@ buckets_rm_key_get_keys(buckets, key);
        //@ buckets_remove_key_chains_still_start_on_hash(buckets, real_capacity, key);
        //@ buckets_remove_key_same_len(buckets, key);
        //@ close buckets_keys_insync(real_capacity, chains_lst, buckets_remove_key_fp(buckets, key), update(index_of(some(key), key_opts), none, key_opts));
        //@ close mapp_core(key_size, real_capacity, kaddrs_lst, _, hashes_lst, values_lst, _, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key));
        //@ close mapp(map, key_size, capacity, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key));
        return;
      }
      //@ recover_key_opt_list(kaddrs_lst, busybits_lst, key_opts, index);
    } else {
      //@ if (bb) no_hash_no_key(key_opts, hashes_lst, key, index); else no_bb_no_key(key_opts, busybits_lst, index);
    }
    //@ buckets_remove_key_same_len(buckets, key);
    //@ buckets_keys_chns_same_len(buckets_remove_key_fp(buckets, key));
    //@ buckets_get_chain_longer(buckets, start, i, key, real_capacity);
    //@ buckets_get_chns_nonneg(buckets_remove_key_fp(buckets, key));
    //@ add_part_chn_gt0(index, buckets_get_chain_fp(buckets, key, start) - i, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
    //@ produce_limits(chn);
    map->chains[index] = chn - 1;
    //@ assert nth(index, key_opts) != some(key);
    //@ assert true == neq(some(key), nth(index, key_opts));
    //@ assert true == neq(some(key), nth(loop_fp(i+start, real_capacity), key_opts));
    //@ assert nat_of_int(i+1) == succ(nat_of_int(i));
    //@ buckets_keys_chns_same_len(buckets);
    //@ assert length(buckets) == real_capacity;
    //@ assert length(chains_lst) == length(buckets);
    //@ buckets_remove_key_same_len(buckets, key);
    //@ buckets_keys_chns_same_len(buckets_remove_key_fp(buckets, key));
    //@ add_partial_chain_same_len(start + i, buckets_get_chain_fp(buckets, key, start) - i, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
    //@ loop_fixp(start + i, real_capacity);
    //@ buckets_ok_get_chain_bounded(buckets, key, start);
    //@ remove_one_cell_from_partial_chain(chains_lst, loop_fp(start + i, real_capacity), buckets_get_chain_fp(buckets, key, start) - i, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)), real_capacity);
    //@ assert map->chains |-> ?chains_ptr;
    //@ assert chains_ptr[0..real_capacity] |-> update(index, nth(index, chains_lst) - 1, add_partial_chain_fp(loop_fp(start + i, real_capacity), buckets_get_chain_fp(buckets, key, start) - i, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key))));
    //@ assert chains_ptr[0..real_capacity] |-> add_partial_chain_fp(loop_fp(loop_fp(start + i, real_capacity) + 1, real_capacity), buckets_get_chain_fp(buckets, key, start) - i - 1, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
    //@ inc_modulo_loop(start + i, real_capacity);
    //@ assert loop_fp(loop_fp(start + i, real_capacity) + 1, real_capacity) == loop_fp(start + i + 1, real_capacity);
    //@ chains_lst = add_partial_chain_fp(loop_fp(start + i + 1, real_capacity), buckets_get_chain_fp(buckets, key, start) - i - 1, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
    //@ assert chains_ptr[0..real_capacity] |-> add_partial_chain_fp(loop_fp(start + i + 1, real_capacity), buckets_get_chain_fp(buckets, key, start) - i - 1, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
    //@ close mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
  }
  //@ open mapp_core(key_size, real_capacity, kaddrs_lst, busybits_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
  //@ by_loop_for_all(key_opts, (neq)(some(key)), start, real_capacity, nat_of_int(real_capacity));
  //@ no_key_found(key_opts, key);
  //@ assert false;
}
