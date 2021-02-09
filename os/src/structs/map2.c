#include "structs/map2.h"

// This implementation is mostly a copy-paste of the raw map

#include "os/memory.h"

//@ #include "proof/chain-buckets.gh"
//@ #include "proof/listexex.gh"
//@ #include "proof/modulo.gh"
//@ #include "proof/mod-pow2.gh"
//@ #include "proof/nth-prop.gh"
//@ #include "proof/sizeex.gh"
//@ #include "proof/stdex.gh"

// !!! IMPORTANT !!!
// To verify, 'default_value_eq_zero' needs to be turned from a lemma_auto to a lemma in prelude_core.gh, see verifast issue 68

struct os_map2 {
  char* keys;
  bool* busybits;
  hash_t* hashes;
  size_t* chains;
  char* values;
  size_t key_size;
  size_t value_size;
  size_t capacity;
};

/*@
  predicate objects(char* ptr, size_t size, size_t count; list<list<char> > objs) =
    count == 0 ? objs == nil
               : (chars(ptr, size, ?obj) &*&
                  objects(ptr + size, size, count - 1, ?objst) &*&
                  objs == cons(obj, objst) &*&
                  length(objs) == count);

  fixpoint size_t opts_size(list<option<list<char> > > opts) {
    switch(opts) {
      case nil: return 0;
      case cons(h,t): return (h == none ? 0 : 1) + opts_size(t);
    }
  }

  // Keys + busybits => key options
  predicate key_opt_list(list<list<char> > keys, list<bool> busybits;
                         list<option<list<char> > > key_opts) =
    switch(busybits) {
      case nil:
        return keys == nil &*& key_opts == nil;
      case cons(bbh, bbt):
        return keys == cons(?keysh, ?keyst) &*&
               key_opt_list(keyst, bbt, ?key_optst) &*&
               bbh ? (key_opts == cons(some(keysh), key_optst)) : (key_opts == cons(none, key_optst));
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

  // Key options + values => items
  // NOTE: It is crucial that this predicate be expressed without using ghostmap_set!
  //       Using set would impose an order, which makes the rest of the proof (probably?) infeasible.
  predicate map_items(list<option<list<char> > > key_opts, list<list<char> > values,
                      list<pair<list<char>, list<char> > > items) =
    switch(key_opts) {
      case nil:
        return values == nil &*&
               items == nil;
      case cons(key_optsh, key_optst):
        return values == cons(?valuesh, ?valuest) &*&
               map_items(key_optst, valuest, ?items_rest) &*&
               true == ghostmap_distinct(items) &*&
               switch(key_optsh) {
                 case none: return items == items_rest;
                 case some(kohv): return items_rest == ghostmap_remove(items, kohv) &*&
                                         some(valuesh) == ghostmap_get(items, kohv);
               };
    };

  // Keys + busybits + hashes + values => key options + map values + map addresses
  predicate mapp2_core(size_t capacity,
                       list<list<char> > keys, list<bool> busybits, list<hash_t> hashes, list<list<char> > values,
                       list<option<list<char> > > key_opts, list<pair<list<char>, list<char> > > items) =
     key_opt_list(keys, busybits, key_opts) &*&
     map_items(key_opts, values, items) &*&
     hash_list(key_opts, hashes) &*&
     true == opt_no_dups(key_opts) &*&
     true == ghostmap_distinct(items) &*&
     length(key_opts) == capacity &*&
     opts_size(key_opts) <= length(key_opts) &*&
     opts_size(key_opts) == length(items);

  // Map => its contents
  predicate mapp2_raw(struct os_map2* map;
                      list<list<char> > keys, list<bool> busybits, list<hash_t> hashes, list<size_t> chains, list<list<char> > values, 
                      size_t key_size, size_t value_size, size_t capacity) =
    struct_os_map2_padding(map) &*&
    map->keys |-> ?keys_ptr &*&
    map->busybits |-> ?busybits_ptr &*&
    map->hashes |-> ?hashes_ptr &*&
    map->chains |-> ?chains_ptr &*&
    map->values |-> ?values_ptr &*&
    map->key_size |-> key_size &*&
    map->value_size |-> value_size &*&
    map->capacity |-> capacity &*&
    objects(keys_ptr, key_size, capacity, keys) &*&
    busybits_ptr[0..capacity] |-> busybits &*&
    hashes_ptr[0..capacity] |-> hashes &*&
    chains_ptr[0..capacity] |-> chains &*&
    objects(values_ptr, value_size, capacity, values) &*&
    key_size > 0 &*&
    key_size * capacity <= SIZE_MAX &*&
    keys_ptr + (key_size * capacity) <= (char*)UINTPTR_MAX &*&
    value_size > 0 &*&
    value_size * capacity <= SIZE_MAX &*&
    values_ptr + (value_size * capacity) <= (char*)UINTPTR_MAX;

  // Combine everything, including the chains optimization
  predicate mapp2(struct os_map2* map, size_t key_size, size_t value_size, size_t capacity, list<pair<list<char>, list<char> > > items) =
    mapp2_raw(map, ?keys, ?busybits, ?hashes, ?chains, ?values, key_size, value_size, ?real_capacity) &*&
    mapp2_core(real_capacity, keys, busybits, hashes, values, ?key_opts, items) &*&
    buckets_keys_insync(real_capacity, chains, ?buckets, key_opts) &*&
    capacity == 0 ? real_capacity == 0
                  : (real_capacity >= capacity &*&
                     real_capacity <= SIZE_MAX / 2 &*&
                     is_pow2(real_capacity, N63) != none);
@*/

static size_t get_real_capacity(size_t capacity)
//@ requires capacity <= SIZE_MAX / 2;
/*@ ensures capacity == 0 ? result == 0 :
                            (result >= capacity &*&
                             result <= capacity * 2 &*&
                             is_pow2(result, N63) != none); @*/
{
  if (capacity == 0) {
    return 0;
  }
  size_t real_capacity = 1;
  while (real_capacity < capacity)
  /*@ invariant is_pow2(real_capacity, N63) != none &*&
                real_capacity <= capacity * 2; @*/
  {
    real_capacity *= 2;
  }
  //@ assert none != is_pow2(real_capacity, N63);
  return real_capacity;
}

static size_t loop(size_t start, size_t i, size_t capacity)
/*@ requires i < capacity &*&
             is_pow2(capacity, N63) != none &*&
             capacity <= SIZE_MAX / 2; @*/
/*@ ensures 0 <= result &*& result < capacity &*&
            result == loop_fp(start + i, capacity) &*&
            0 <= loop_fp(start, capacity) &*& loop_fp(start, capacity) < capacity &*&
            result == loop_fp(loop_fp(start, capacity) + i, capacity); @*/
{
  //@ nat m = is_pow2_some(capacity, N63);
  //@ mod_bitand_equiv(start, capacity, m);
  //@ div_mod_gt_0(start % capacity, start, capacity);
  size_t startmod = start & (capacity - 1);
  //@ mod_bitand_equiv(startmod + i, capacity, m);
  //@ div_mod_gt_0((startmod + i) % capacity, startmod + i, capacity);
  //@ mod_mod(start, i, capacity);
  return (startmod + i) & (capacity - 1);
}

/*@
lemma void empty_bytes_to_objects(char* ptr, size_t size, size_t count)
  requires chars(ptr, size * count, ?cs) &*&
           0 < size &*&
           0 <= count;
  ensures objects(ptr, size, count, ?objs) &*&
          length(objs) == count;
{
  for (int n = count; n > 0; n--)
    invariant count >= n &*& n >= 0 &*&
              objects(ptr + (n * size), size, count - n, ?objs_prev) &*&
              length(objs_prev) == count - n &*&
              chars(ptr, size * n, ?cs_next);
    decreases n;
  {
    mul_nonnegative(size, n - 1);
    chars_split(ptr, size * (n - 1));
    close objects(ptr + ((n - 1) * size), size, count - (n - 1), ?objs_next);
  }
}

// ---

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

lemma void produce_key_opt_list(list<hash_t> hashes, list<list<char> > keys)
  requires length(hashes) == length(keys);
  ensures key_opt_list(keys, repeat_n(nat_of_int(length(keys)), false), repeat_n(nat_of_int(length(keys)), none)) &*&
          length(keys) == length(repeat_n(nat_of_int(length(keys)), none));
{
  switch(keys) {
    case nil:
      close key_opt_list(keys, repeat_n(nat_of_int(length(keys)), false), repeat_n(nat_of_int(length(keys)), none));
    case cons(keysh, keyst):
      switch(hashes) {
        case nil:
        case cons(hh,ht):
      }
      produce_key_opt_list(tail(hashes), keyst);
      nat_len_of_non_nil(keysh, keyst);
      close key_opt_list(keys, repeat_n(nat_of_int(length(keys)), false), repeat_n(nat_of_int(length(keys)), none));
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

lemma void produce_empty_map_items(size_t capacity, list<option<list<char> > > key_opts, list<list<char> > values)
  requires length(key_opts) == length(values) &*& length(key_opts) == capacity;
  ensures map_items(repeat_n(nat_of_int(capacity), none), values, nil);
{
  switch(key_opts) {
    case nil:
      length_0_nil(values);
      close map_items(repeat_n(nat_of_int(capacity), none), values, nil);
    case cons(key_optsh, key_optst):
      assert values == cons(?valuesh, ?valuest);
      assert capacity > 0;
      repeat_n_length(nat_of_int(capacity), none);
      assert repeat_n(nat_of_int(capacity), none) == cons(?noh, ?not);
      repeat_n_is_n(nat_of_int(capacity), none);
      assert noh == none;
      produce_empty_map_items(capacity - 1, key_optst, valuest);
      repeat_n_tail(nat_of_int(capacity), none);
      assert not == repeat_n(nat_of_int(capacity-1), none);
      assert true == distinct(nil);
      close map_items(repeat_n(nat_of_int(capacity), none), values, nil);
  }
}
@*/

struct os_map2* os_map2_alloc(size_t key_size, size_t value_size, size_t capacity)
/*@ requires key_size > 0 &*&
             key_size * capacity * 2 <= SIZE_MAX &*&
             value_size > 0 &*&
             value_size * capacity * 2 <= SIZE_MAX &*&
             capacity * sizeof(size_t) * 2 <= SIZE_MAX; @*/
/*@ ensures mapp2(result, key_size, value_size, capacity, nil); @*/
{
  struct os_map2* map = (struct os_map2*) os_memory_alloc(1, sizeof(struct os_map2));
  //@ close_struct_zero(map);
  //@ mul_mono(1, key_size, capacity);
  size_t real_capacity = get_real_capacity(capacity);
  //@ mul_bounds(real_capacity, capacity * 2, key_size, key_size);
  map->keys = (char*) os_memory_alloc(real_capacity, key_size);
  map->busybits = (bool*) os_memory_alloc(real_capacity, sizeof(bool));
  map->hashes = (hash_t*) os_memory_alloc(real_capacity, sizeof(hash_t));
  map->chains = (size_t*) os_memory_alloc(real_capacity, sizeof(size_t));
  //@ mul_bounds(real_capacity, capacity * 2, value_size, value_size);
  map->values = (char*) os_memory_alloc(real_capacity, value_size);
  map->capacity = real_capacity;
  map->key_size = key_size;
  map->value_size = value_size;
  // TODO extend VeriFast to understand that since map->busybits and map->chains are zeroed chars, they are zeroed bools/size_ts
  for (size_t i = 0; i < real_capacity; ++i)
    /*@ invariant map->busybits |-> ?busybits_ptr &*&
                  busybits_ptr[0..i] |-> repeat_n(nat_of_int(i), false) &*&
                  busybits_ptr[i..real_capacity] |-> ?busybits_rest &*&
                  map->chains |-> ?chains_ptr &*&
                  chains_ptr[0..i] |-> repeat_n(nat_of_int(i), 0) &*&
                  chains_ptr[i..real_capacity] |-> ?chains_rest &*&
                  0 <= i &*& i <= real_capacity; @*/
  {
    //@ move_busybit(busybits_ptr, i, real_capacity);
    //@ move_chain(chains_ptr, i, real_capacity);
    //@ assert busybits_rest == cons(?bbrh, _);
    //@ assert chains_rest == cons(?crh, _);
    //@ extend_repeat_n(nat_of_int(i), bbrh, false);
    //@ extend_repeat_n(nat_of_int(i), crh, 0);
    map->busybits[i] = false;
    map->chains[i] = 0;
    //@ assert succ(nat_of_int(i)) == nat_of_int(i+1);
  }
  //@ assert map->keys |-> ?keys_ptr;
  //@ empty_bytes_to_objects(keys_ptr, key_size, real_capacity);
  //@ assert map->values |-> ?values_ptr;
  //@ empty_bytes_to_objects(values_ptr, value_size, real_capacity);
  //@ close mapp2_raw(map, ?keys_lst, ?busybits_lst, ?hashes_lst, ?chains_lst, ?values_lst, key_size, value_size, real_capacity);
  //@ produce_key_opt_list(hashes_lst, keys_lst);
  //@ assert key_opt_list(keys_lst, _, ?kopts);
  //@ repeat_n_contents(nat_of_int(real_capacity), none);
  //@ kopts_size_0_when_empty(kopts);
  //@ empty_buckets_insync(repeat_n(nat_of_int(real_capacity), 0), real_capacity);
  //@ produce_empty_map_items(real_capacity, kopts, values_lst);
  //@ produce_empty_hash_list(kopts, hashes_lst);
  //@ repeat_none_is_opt_no_dups(nat_of_int(real_capacity), kopts);
  //@ close mapp2_core(real_capacity, keys_lst, _, hashes_lst, values_lst, kopts, nil);
  //@ close mapp2(map, key_size, value_size, capacity, nil);
  return map;
}


/*@
lemma list<char> extract_key_at_index(list<list<char> > keys_b, list<bool> busybits_b, list<option<list<char> > > key_opts_b, size_t n, 
                                      list<bool> busybits, list<option<list<char> > > key_opts)
  requires key_opt_list(?keys, busybits, key_opts) &*&
           key_opt_list(keys_b, busybits_b, key_opts_b) &*&
           0 <= n &*& n < length(busybits) &*& true == nth(n, busybits);
  ensures nth(n, key_opts) == some(nth(n, keys)) &*&
          key_opt_list(drop(n+1, keys), drop(n+1, busybits), drop(n+1, key_opts)) &*&
          key_opt_list(append(reverse(take(n, keys)), keys_b),
                       append(reverse(take(n, busybits)), busybits_b),
                       append(reverse(take(n, key_opts)), key_opts_b));
{
  open key_opt_list(keys, _, _);
  switch(busybits) {
    case nil:
      return nil;
    case cons(bbh, bbt):
      switch(keys) {
        case nil: return nil;
        case cons(keysh, keyst):
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
              close key_opt_list(cons(keysh, keys_b), cons(bbh, busybits_b), cons(kh, key_opts_b));
              append_reverse_take_cons(n,keysh,keyst,keys_b);
              append_reverse_take_cons(n,bbh,bbt,busybits_b);
              append_reverse_take_cons(n,kh,kt,key_opts_b);
              return extract_key_at_index(cons(keysh,keys_b),
                                          cons(bbh,busybits_b),
                                          cons(kh, key_opts_b),
                                          n-1, bbt, kt);
            }
          }
      }
  }
}

// ---

lemma void extract_object(char* ptr, int index)
  requires objects(ptr, ?size, ?count, ?objs) &*&
           0 <= index &*& index < count;
  ensures objects(ptr, size, index, take(index, objs)) &*&
          chars(ptr + (index * size), size, nth(index, objs)) &*&
          objects(ptr + ((index + 1) * size), size, count - (index + 1), drop(index + 1, objs));
{
  open objects(ptr, size, count, objs);
  switch(objs) {
    case nil:
      assert false;
    case cons(h, t):
      if (index == 0) {
        return;
      }
      extract_object(ptr + size, index - 1);
      close objects(ptr, size, index, _);
  }
}

// ---

lemma void stitch_objects(char* ptr, int index, int count)
  requires 0 <= index &*& index < count &*&
           objects(ptr, ?size, index, ?objs_h) &*&
           chars(ptr + (index * size), size, ?obj) &*&
           objects(ptr + ((index + 1) * size), size, count - (index + 1), ?objs_t);
  ensures objects(ptr, size, count, append(objs_h, cons(obj, objs_t)));
{
  open objects(ptr + ((index + 1) * size), size, count - (index + 1), objs_t);
  assert length(objs_t) == count - (index + 1);
  close objects(ptr + ((index + 1) * size), size, count - (index + 1), objs_t);
  close objects(ptr + (index * size), size, count - index, cons(obj, objs_t));
  open objects(ptr, size, index, objs_h);
  assert length(objs_h) == index;
  close objects(ptr, size, index, objs_h);
  for (int n = index; n >= 1; n--)
    invariant index >= n &*& n >= 0 &*&
              objects(ptr, size, n, take(n, objs_h)) &*&
              objects(ptr + (n * size), size, count - n, append(drop(n, objs_h), cons(obj, objs_t)));
    decreases n - 1;
  {
    extract_object(ptr, n - 1);
    close objects(ptr + ((n - 1) * size), size, count - (n - 1), ?new_objs);
    take_take(n-1, n, objs_h);
    drop_except_last(objs_h, n-1);
  }
}

// ---

lemma void reconstruct_key_opt_list(list<list<char> > keys1, list<bool> busybits1, 
                                    list<list<char> > keys2, list<bool> busybits2)
  requires key_opt_list(keys1, busybits1, ?key_opts1) &*&
           key_opt_list(keys2, busybits2, ?key_opts2);
  ensures key_opt_list(append(reverse(keys1), keys2),
                       append(reverse(busybits1), busybits2),
                       append(reverse(key_opts1), key_opts2));
{
  open key_opt_list(keys1, busybits1, key_opts1);
  switch(busybits1) {
    case nil:
      assert(keys1 == nil);
      assert(key_opts1 == nil);
    case cons(bbh, bbt):
      append_reverse_tail_cons_head(keys1, keys2);
      append_reverse_tail_cons_head(busybits1, busybits2);
      append_reverse_tail_cons_head(key_opts1, key_opts2);
      assert keys1 == cons(?keysh, ?keyst);
      assert key_opts1 == cons(?ko1h, _);
      close key_opt_list(cons(keysh, keys2), cons(bbh, busybits2), cons(ko1h, key_opts2));
      reconstruct_key_opt_list(keyst, bbt, cons(keysh, keys2), cons(bbh, busybits2));
  }
}

lemma void recover_key_opt_list(list<list<char> > keys, list<bool> busybits, list<option<list<char> > > key_opts, size_t n)
  requires key_opt_list(reverse(take(n, keys)), reverse(take(n, busybits)), reverse(take(n, key_opts))) &*&
           true == nth(n, busybits) &*&
           nth(n, key_opts) == some(nth(n, keys)) &*&
           key_opt_list(drop(n+1, keys), drop(n+1, busybits), drop(n+1, key_opts)) &*&
           0 <= n &*& n < length(keys) &*&
           n < length(busybits) &*&
           n < length(key_opts);
  ensures key_opt_list(keys, busybits, key_opts);
{
  close key_opt_list(cons(nth(n, keys), drop(n+1,keys)),
                     cons(nth(n, busybits), drop(n+1,busybits)),
                     cons(nth(n, key_opts), drop(n+1, key_opts)));
  drop_n_plus_one(n, keys);
  drop_n_plus_one(n, busybits);
  drop_n_plus_one(n, key_opts);
  reconstruct_key_opt_list(reverse(take(n, keys)),
                           reverse(take(n, busybits)),
                           drop(n, keys),
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
  requires key_opt_list(?keys, busybits, key_opts) &*& 0 <= i &*& i < length(key_opts) &*&
           false == nth(i, busybits);
  ensures key_opt_list(keys, busybits, key_opts) &*& nth(i, key_opts) == none;
{
  open key_opt_list(keys, busybits, key_opts);
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
  close key_opt_list(keys, busybits, key_opts);
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

lemma void map_items_reflects_keyopts_mem<k,v>(list<char> key, size_t idx)
requires map_items(?key_opts, ?values, ?items) &*&
         true == ghostmap_distinct(items) &*&
         true == mem(some(key), key_opts) &*&
         idx == index_of(some(key), key_opts);
ensures map_items(key_opts, values, items) &*&
        ghostmap_get(items, key) == some(nth(idx, values));
{
  open map_items(key_opts, values, items);
  switch(key_opts) {
    case nil:
      assert false;
    case cons(key_optsh, key_optst):
      if (idx != 0) {
        map_items_reflects_keyopts_mem(key, idx - 1);
        switch(key_optsh) {
          case none:
          case some(kohv):
            ghostmap_remove_preserves_other(items, kohv, key);
        }
      }
      close map_items(key_opts, values, items);
  }
}

// ---

lemma void key_opts_has_not_implies_map_items_has_not(list<char> key)
requires map_items(?key_opts, ?values, ?items) &*&
         false == mem(some(key), key_opts);
ensures map_items(key_opts, values, items) &*&
        ghostmap_get(items, key) == none;
{
  open map_items(key_opts, values, items);
  switch(key_opts) {
    case nil:
    case cons(key_optsh, key_optst):
      key_opts_has_not_implies_map_items_has_not(key);
      switch (key_optsh) {
        case none:
        case some(kohv):
          ghostmap_remove_preserves_other(items, kohv, key);
      }
  }
  close map_items(key_opts, values, items);
}
@*/

bool os_map2_get(struct os_map2* map, void* key_ptr, void* out_value_ptr)
/*@ requires mapp2(map, ?key_size, ?value_size, ?capacity, ?items) &*&
             [?f]chars(key_ptr, key_size, ?key) &*&
             chars(out_value_ptr, value_size, _); @*/
/*@ ensures mapp2(map, key_size, value_size, capacity, items) &*&
            [f]chars(key_ptr, key_size, key) &*&
            switch(ghostmap_get(items, key)) {
              case none: return result == false &*& chars(out_value_ptr, value_size, _);
              case some(v): return result == true &*& chars(out_value_ptr, value_size, v);
            }; @*/
{
  //@ open mapp2(map, key_size, value_size, capacity, items);
  hash_t key_hash = os_memory_hash(key_ptr, map->key_size);
  for (size_t i = 0; i < map->capacity; ++i)
    /*@ invariant mapp2_raw(map, ?keys_lst, ?busybits_lst, ?hashes_lst, ?chains_lst, ?values_lst, key_size, value_size, ?real_capacity) &*&
                  mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, ?key_opts, items) &*&
                  buckets_keys_insync(real_capacity, chains_lst, ?buckets, key_opts) &*&
                  0 <= i &*& i <= real_capacity &*&
                  [f]chars(key_ptr, key_size, key) &*&
                  chars(out_value_ptr, value_size, _) &*&
                  hash_fp(key) == key_hash &*&
                  capacity == 0 ? real_capacity == 0 :
                                  (real_capacity >= capacity &*&
                                   real_capacity <= SIZE_MAX / 2 &*&
                                   is_pow2(real_capacity, N63) != none) &*&
                  true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, loop_fp(key_hash, real_capacity))); @*/
  {
    //@ open mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items);
    //@ open buckets_keys_insync(real_capacity, chains_lst, buckets, key_opts);
    size_t index = loop(key_hash, i, map->capacity);
    bool bb = map->busybits[index];
    hash_t kh = map->hashes[index];
    size_t chn = map->chains[index];
    //@ open mapp2_raw(map, keys_lst, busybits_lst, hashes_lst, chains_lst, values_lst, key_size, value_size, real_capacity);
    //@ assert map->keys |-> ?keys_ptr;
    //@ open objects(keys_ptr, key_size, real_capacity, keys_lst);
    //@ assert length(keys_lst) == real_capacity;
    //@ close objects(keys_ptr, key_size, real_capacity, keys_lst);
    //@ assert map->values |-> ?values_ptr;
    //@ open objects(values_ptr, value_size, real_capacity, values_lst);
    //@ assert length(values_lst) == real_capacity;
    //@ close objects(values_ptr, value_size, real_capacity, values_lst);
    //@ mul_bounds(key_size, key_size, index, real_capacity);
    char* kp = map->keys + (index * map->key_size);
    if (bb && kh == key_hash) {
      //@ close key_opt_list(nil, nil, nil);
      //@ extract_key_at_index(nil, nil, nil, index, busybits_lst, key_opts);
      //@ append_nil(reverse(take(index, keys_lst)));
      //@ append_nil(reverse(take(index, busybits_lst)));
      //@ append_nil(reverse(take(index, key_opts)));
      //@ extract_object(keys_ptr, index);
      if (os_memory_eq(kp, key_ptr, map->key_size)) {
        //@ stitch_objects(keys_ptr, index, real_capacity);
        //@ recover_key_opt_list(keys_lst, busybits_lst, key_opts, index);
        //@ open map_items(key_opts, values_lst, items);
        //@ assert true == opt_no_dups(key_opts);
        //@ close map_items(key_opts, values_lst, items);
        //@ key_opt_list_find_key(key_opts, index, key);
        //@ close buckets_keys_insync(real_capacity, chains_lst, buckets, key_opts);
        //@ map_items_reflects_keyopts_mem(key, index);
        //@ mul_bounds(value_size, value_size, index, real_capacity);
        //@ extract_object(values_ptr, index);
        os_memory_copy(map->values + (index * map->value_size), out_value_ptr, map->value_size);
        //@ stitch_objects(values_ptr, index, real_capacity);
        //@ close mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items);
        //@ drop_cons(keys_lst, index);
        //@ drop_cons(values_lst, index);
        //@ close mapp2_raw(map, keys_lst, busybits_lst, hashes_lst, chains_lst, values_lst, key_size, value_size, real_capacity);
        //@ close mapp2(map, key_size, value_size, capacity, items);
        return true;
      }
      //@ stitch_objects(keys_ptr, index, real_capacity);
      //@ recover_key_opt_list(keys_lst, busybits_lst, key_opts, index);
    } else {
      //@ if (bb) no_hash_no_key(key_opts, hashes_lst, key, index); else no_bb_no_key(key_opts, busybits_lst, index);
      if (chn == 0) {
        //@ assert length(chains_lst) == real_capacity;
        //@ buckets_keys_chns_same_len(buckets);
        //@ assert length(buckets) == real_capacity;
        //@ no_crossing_chains_here(buckets, index);
        //@ assert nil == get_crossing_chains_fp(buckets, index);
        //@ key_is_contained_in_the_bucket(buckets, real_capacity, key);
        //@ assert true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, loop_fp(hash_fp(key), real_capacity)));
        //@ assert true == up_to(succ(nat_of_int(i)), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, loop_fp(hash_fp(key), real_capacity)));
        //@ assert true == up_to(nat_of_int(i+1), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, loop_fp(hash_fp(key), real_capacity)));
        //@ assert buckets != nil;
        //@ chains_depleted_no_hope(buckets, i, loop_fp(hash_fp(key), real_capacity), key, real_capacity);
        //@ assert false == mem(some(key), key_opts);
        //@ key_opts_has_not_implies_map_items_has_not(key);
        //@ close buckets_keys_insync(real_capacity, chains_lst, buckets, key_opts);
        //@ close mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items);
        //@ close mapp2_raw(map, keys_lst, busybits_lst, hashes_lst, chains_lst, values_lst, key_size, value_size, real_capacity);
        //@ close mapp2(map, key_size, value_size, capacity, items);
        return false;
      }
      //@ assert(length(key_opts) == real_capacity);
    }
    //@ assert(nth(index, key_opts) != some(key));
    //@ assert(true == neq(some(key), nth(index, key_opts)));
    //@ assert(true == neq(some(key), nth(loop_fp(i+key_hash, real_capacity), key_opts)));
    //@ assert(true == neq(some(key), nth(loop_fp(i+loop_fp(key_hash, real_capacity), real_capacity), key_opts)));
    //@ assert(nat_of_int(i+1) == succ(nat_of_int(i)));
    //@ close buckets_keys_insync(real_capacity, chains_lst, buckets, key_opts);
    //@ close mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items);
    //@ drop_cons(keys_lst, index);
    //@ close mapp2_raw(map, keys_lst, busybits_lst, hashes_lst, chains_lst, values_lst, key_size, value_size, real_capacity);
  }
  //@ open mapp2_core(?real_capacity, ?keys_lst, ?busybits_lst, ?hashes_lst, ?values_lst, ?key_opts, items);
  //@ assert buckets_keys_insync(real_capacity, ?chains_lst, ?buckets, key_opts);
  /*@ if (real_capacity != 0) {
        loop_lims(key_hash, real_capacity); 
        by_loop_for_all(key_opts, (neq)(some(key)), loop_fp(key_hash, real_capacity), real_capacity, nat_of_int(real_capacity)); 
      } @*/
  //@ no_key_found(key_opts, key);
  //@ key_opts_has_not_implies_map_items_has_not(key);
  //@ close mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items);
  //@ close mapp2(map, key_size, value_size, capacity, items);
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
  requires key_opt_list(?keys, busybits,  key_opts) &*&
           false == nth(i, busybits) &*&
           0 <= i &*& i < length(busybits);
  ensures key_opt_list(keys, busybits, key_opts) &*&
          nth(i, key_opts) == none &*&
          opts_size(key_opts) < length(key_opts);
{
  open key_opt_list(keys, busybits, key_opts);
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
  close key_opt_list(keys, busybits, key_opts);
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
  requires key_opt_list(?keys, busybits, key_opts) &*&
           true == nth(i, busybits) &*&
           0 <= i &*& i < length(busybits);
  ensures key_opt_list(keys, busybits, key_opts) &*&
          true == cell_busy(nth(i, key_opts));
  {
    open key_opt_list(keys, busybits, key_opts);
    switch(busybits) {
      case nil:
      case cons(h,t):
      if (i == 0) {
      } else {
        nth_cons(i, t, h);
        bb_nonzero_cell_busy(t, tail(key_opts), i-1);
      }
    }
    close key_opt_list(keys, busybits, key_opts);
  }

// ---

lemma void put_keeps_key_opt_list(list<list<char> > keys, list<bool> busybits, list<option<list<char> > > key_opts, int index, list<char> k)
  requires key_opt_list(keys, busybits, key_opts) &*&
           0 <= index &*& index < length(busybits) &*&
           nth(index, key_opts) == none;
  ensures key_opt_list(update(index, k, keys), update(index, true, busybits), update(index, some(k), key_opts));
{
  open key_opt_list(keys, busybits, key_opts);
  switch(busybits) {
    case nil:
    case cons(bbh, bbt):
      assert keys == cons(?keysh, ?keyst);
      assert key_opts == cons(?koh, ?kot);
      if (index == 0) {
        tail_of_update_0(keys, k);
        tail_of_update_0(key_opts, some(k));
        head_update_0(k, keys);
      } else {
        put_keeps_key_opt_list(keyst, bbt, kot, index-1, k);
        cons_head_tail(keys);
        cons_head_tail(key_opts);
        update_tail_tail_update(keysh, keyst, index, k);
        update_tail_tail_update(koh, kot, index, some(k));
        update_tail_tail_update(bbh, bbt, index, true);
      }
      update_non_nil(keys, index, k);
      update_non_nil(key_opts, index, some(k));
  }
  close key_opt_list(update(index, k, keys), update(index, true, busybits), update(index, some(k), key_opts));
}

// ---

lemma void map_items_has_not_implies_key_opts_has_not(list<pair<list<char>, list<char> > > items, list<option<list<char> > > key_opts, list<char> key)
requires map_items(key_opts, ?values, items) &*&
         ghostmap_get(items, key) == none;
ensures map_items(key_opts, values, items) &*&
        false == mem(some(key), key_opts);
{
  switch(key_opts) {
    case nil:
    case cons(key_optsh, key_optst):
      switch(key_optsh) {
        case none:
          open map_items(key_opts, values, items);
          map_items_has_not_implies_key_opts_has_not(items, key_optst, key);
          close map_items(key_opts, values, items);
        case some(kohv):
          open map_items(key_opts, values, items);
          assert values == cons(?valuesh, ?valuest);
          assert map_items(key_optst, valuest, ?items_rest);
          ghostmap_remove_preserves_other(items, kohv, key);
          map_items_has_not_implies_key_opts_has_not(items_rest, key_optst, key);
          close map_items(key_opts, values, items);
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

lemma void put_updates_items(size_t index, list<char> key, list<char> value)
  requires map_items(?key_opts, ?values, ?items) &*&
           0 <= index &*& index < length(key_opts) &*&
           nth(index, key_opts) == none &*&
           false == mem(some(key), key_opts) &*&
           ghostmap_get(items, key) == none;
  ensures map_items(update(index, some(key), key_opts),
                    update(index, value, values),
                    ghostmap_set(items, key, value));
{
  switch(key_opts) {
    case nil:
    case cons(key_optsh, key_optst):
      open map_items(key_opts, values, items);
      if (index == 0) {
        ghostmap_remove_cancels_set(items, key, value);
      } else {
        switch(key_optsh) {
          case none:
          case some(kohv):
            ghostmap_remove_preserves_other(items, kohv, key);
            ghostmap_set_remove_different_key_interchangeable(items, key, value, kohv);
            ghostmap_set_preserves_other(items, key, value, kohv);
        }
        put_updates_items(index - 1, key, value);
      }
      ghostmap_set_new_preserves_distinct(items, key, value);
      close map_items(update(index, some(key), key_opts),
                      update(index, value, values),
                      ghostmap_set(items, key, value));
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

// ---

lemma void stitched_is_update<t>(list<t> lst, int index, t value)
  requires 0 <= index &*& index < length(lst);
  ensures append(take(index, lst), cons(value, drop(index + 1, lst))) == update(index, value, lst);
{
  switch(lst) {
    case nil:
    case cons(h, t):
      if (index != 0) {
        stitched_is_update(t, index - 1, value);
      }
  }
}
@*/

bool os_map2_set(struct os_map2* map, void* key_ptr, void* value_ptr)
/*@ requires mapp2(map, ?key_size, ?value_size, ?capacity, ?items) &*&
             [?kf]chars(key_ptr, key_size, ?key) &*&
             [?vf]chars(value_ptr, value_size, ?value) &*&
             length(items) < capacity &*&
             ghostmap_get(items, key) == none; @*/
/*@ ensures [kf]chars(key_ptr, key_size, key) &*&
            [vf]chars(value_ptr, value_size, value) &*&
            mapp2(map, key_size, value_size, capacity, ghostmap_set(items, key, value)); @*/
{
  //@ open mapp2(map, key_size, value_size, capacity, items);
  hash_t key_hash = os_memory_hash(key_ptr, map->key_size);
  //@ assert buckets_keys_insync(?real_capacity, ?old_chains_lst, ?buckets, ?key_opts);
  //@ size_t start = loop_fp(key_hash, real_capacity);
  //@ loop_lims(key_hash, real_capacity);
  //@ start_Xchain(real_capacity, old_chains_lst, buckets, key_opts, start);
  //@ loop_bijection(start, real_capacity);
  for (size_t i = 0; i < map->capacity; ++i)
    /*@ invariant mapp2_raw(map, ?keys_lst, ?busybits_lst, ?hashes_lst, ?chains_lst, ?values_lst, key_size, value_size, real_capacity) &*&
                  mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items) &*&
                  is_pow2(real_capacity, N63) != none &*&
                  [kf]chars(key_ptr, key_size, key) &*&
                  [vf]chars(value_ptr, value_size, value) &*&
                  0 <= i &*& i <= real_capacity &*&
                  true == up_to(nat_of_int(i),(byLoopNthProp)(key_opts, cell_busy, real_capacity, start)) &*&
                  buckets_keys_insync_Xchain(real_capacity, chains_lst, buckets, start, loop_fp(start + i, real_capacity), key_opts); @*/
  {
    size_t index = loop(key_hash, i, map->capacity);
    //@ open mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items);
    //@ open buckets_keys_insync_Xchain(real_capacity, chains_lst, buckets, start, index, key_opts);
    bool bb = map->busybits[index];
    if (!bb) {
      //@ zero_bbs_is_for_empty(busybits_lst, key_opts, index);
      //@ map_items_has_not_implies_key_opts_has_not(items, key_opts, key);
      //@ open mapp2_raw(map, keys_lst, busybits_lst, hashes_lst, chains_lst, values_lst, key_size, value_size, real_capacity);
      //@ assert map->keys |-> ?keys_ptr;
      //@ open objects(keys_ptr, key_size, real_capacity, keys_lst);
      //@ assert length(keys_lst) == real_capacity;
      //@ close objects(keys_ptr, key_size, real_capacity, keys_lst);
      //@ mul_bounds(key_size, key_size, index, real_capacity);
      //@ extract_object(keys_ptr, index);
      os_memory_copy(key_ptr, map->keys + (index * map->key_size), map->key_size);
      //@ stitch_objects(keys_ptr, index, real_capacity);
      map->busybits[index] = true;
      map->hashes[index] = key_hash;
      //@ assert map->values |-> ?values_ptr;
      //@ open objects(values_ptr, value_size, real_capacity, values_lst);
      //@ assert length(values_lst) == real_capacity;
      //@ close objects(values_ptr, value_size, real_capacity, values_lst);
      //@ mul_bounds(value_size, value_size, index, real_capacity);
      //@ extract_object(values_ptr, index);
      os_memory_copy(value_ptr, map->values + (index * map->value_size), map->value_size);
      //@ stitch_objects(values_ptr, index, real_capacity);
      //@ no_key_in_ks_no_key_in_buckets(buckets, key);
      //@ close buckets_keys_insync_Xchain(real_capacity, chains_lst, buckets, start, index, key_opts);
      //@ buckets_keys_put_key_insync(real_capacity, chains_lst, start, index, key, key_opts);
      //@ put_keeps_key_opt_list(keys_lst, busybits_lst, key_opts, index, key);
      //@ put_updates_items(index, key, value);
      //@ put_preserves_no_dups(key_opts, index, key);
      //@ put_preserves_hash_list(key_opts, hashes_lst, index, key, key_hash);
      //@ put_increases_key_opts_size(key_opts, index, key);
      //@ ghostmap_set_new_preserves_distinct(items, key, value);
      //@ assert true == ghostmap_distinct(ghostmap_set(items, key, value));
      //@ close mapp2_core(real_capacity, ?new_keys_lst, ?new_busybits_lst, ?new_hashes_lst, ?new_values_lst, ?new_key_opts, ?new_items);
      //@ stitched_is_update(keys_lst, index, key);
      //@ stitched_is_update(values_lst, index, value);
      //@ close mapp2(map, key_size, value_size, capacity, new_items);
      return true;
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
    //@ close mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items);
  }
  //@ open mapp2_core(real_capacity, ?keys_lst, ?busybits_lst, ?hashes_lst, ?values_lst, key_opts, items);
  //@ by_loop_for_all(key_opts, cell_busy, start, real_capacity, nat_of_int(real_capacity));
  //@ full_size(key_opts);
  //@ assert false;
  return false;
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
requires key_opt_list(?keys, ?busybits, ?key_opts) &*&
         map_items(key_opts, ?values, ?items) &*&
         0 <= index &*& index < length(key_opts) &*&
         nth(index, key_opts) == some(?key) &*&
         ghostmap_get(items, key) != none &*&
         true == opt_no_dups(key_opts) &*&
         true == ghostmap_distinct(items);
ensures key_opt_list(keys, update(index, false, busybits), update(index, none, key_opts)) &*&
        map_items(update(index, none, key_opts), values, ghostmap_remove(items, key)) &*&
        false == mem(some(key), update(index, none, key_opts));
{
  open key_opt_list(keys, busybits, key_opts);
  open map_items(key_opts, values, items);
  switch(keys) {
    case nil:
    case cons(keysh, keyst):
      assert key_opts == cons(?key_optsh, ?key_optst);
      assert values == cons(?valuesh, ?valuest);
      assert map_items(key_optst, valuest, ?items_rest);
      ghostmap_remove_when_distinct_and_present_decreases_length(items, key);
      if (index == 0) {
        assert busybits == cons(?busybitsh, ?busybitst);
        close map_items(cons(none, key_optst), values, items_rest);
        close key_opt_list(keys, cons(false, busybitst), cons(none, key_optst));
      } else {
        switch(key_optsh) {
          case none:
            map_drop_key(index - 1);
            assert map_items(update(index - 1, none, key_optst), valuest, ?new_items);
            close map_items(update(index, none, key_opts), values, new_items);
            close key_opt_list(keys, update(index, false, busybits), update(index, none, key_opts));
          case some(kohv):
            ghostmap_remove_preserves_other(items, kohv, key);
            map_drop_key(index - 1);
            ghostmap_remove_order_is_irrelevant(items, key, kohv);
            ghostmap_remove_preserves_other(items, key, kohv);
            close map_items(update(index, none, key_opts), values, ghostmap_remove(items, key));
            close key_opt_list(keys, update(index, false, busybits), update(index, none, key_opts));
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

lemma void map_items_has_implies_key_opts_has(list<char> key)
requires map_items(?key_opts, ?values, ?items) &*&
         ghostmap_get(items, key) != none;
ensures map_items(key_opts, values, items) &*&
        true == mem(some(key), key_opts);
{
  open map_items(key_opts, values, items);
  switch(key_opts) {
    case nil:
      assert false;
    case cons(key_optsh, key_optst):
      switch (key_optsh) {
        case none:
          map_items_has_implies_key_opts_has(key);
        case some(kohv):
          if (kohv != key) {
            ghostmap_remove_preserves_other(items, kohv, key);
            map_items_has_implies_key_opts_has(key);
          }
      }
  }
  close map_items(key_opts, values, items);
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

void os_map2_remove(struct os_map2* map, void* key_ptr)
/*@ requires mapp2(map, ?key_size, ?value_size, ?capacity, ?items) &*&
             [?f]chars(key_ptr, key_size, ?key) &*&
             ghostmap_get(items, key) != none; @*/
/*@ ensures [f]chars(key_ptr, key_size, key) &*&
            mapp2(map, key_size, value_size, capacity, ghostmap_remove(items, key)); @*/
{
  //@ open mapp2(map, key_size, value_size, capacity, items);
  hash_t key_hash = os_memory_hash(key_ptr, map->key_size);
  //@ open mapp2_core(?real_capacity, ?keys_lst, ?busybits_lst, ?hashes_lst, ?values_lst, ?key_opts, items);
  //@ map_items_has_implies_key_opts_has(key);
  //@ key_opts_has_implies_not_empty(key_opts, key);
  //@ close mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items);
  //@ size_t start = loop_fp(key_hash, real_capacity);
  //@ loop_lims(key_hash, real_capacity);
  //@ open buckets_keys_insync(real_capacity, ?old_chains_lst, ?buckets, key_opts);
  //@ buckets_keys_chns_same_len(buckets);
  //@ key_is_contained_in_the_bucket(buckets, real_capacity, key);
  //@ buckets_remove_add_one_chain(buckets, start, key);
  //@ loop_bijection(start, real_capacity);
  for (size_t i = 0; i < map->capacity; ++i)
    /*@ invariant mapp2_raw(map, keys_lst, busybits_lst, hashes_lst, ?chains_lst, values_lst, key_size, value_size, real_capacity) &*&
                  mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items) &*&
                  is_pow2(real_capacity, N63) != none &*&
                  0 <= i &*& i <= real_capacity &*&
                  [f]chars(key_ptr, key_size, key) &*&
                  hash_fp(key) == key_hash &*&
                  key_opts == buckets_get_keys_fp(buckets) &*&
                  i <= buckets_get_chain_fp(buckets, key, start) &*&
                  chains_lst == add_partial_chain_fp(loop_fp(start + i, real_capacity), 
                                                     buckets_get_chain_fp(buckets, key, start) - i, 
                                                     buckets_get_chns_fp(buckets_remove_key_fp(buckets, key))) &*&
                  true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, start)); @*/
  {
    //@ open mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items);
    size_t index = loop(key_hash, i, map->capacity);
    bool bb = map->busybits[index];
    hash_t kh = map->hashes[index];
    size_t chn = map->chains[index];
    //@ open mapp2_raw(map, keys_lst, busybits_lst, hashes_lst, chains_lst, values_lst, key_size, value_size, real_capacity);
    //@ assert map->keys |-> ?keys_ptr;
    //@ open objects(keys_ptr, key_size, real_capacity, keys_lst);
    //@ assert length(keys_lst) == real_capacity;
    //@ close objects(keys_ptr, key_size, real_capacity, keys_lst);
    if (bb && kh == key_hash) {
      //@ close key_opt_list(nil, nil, nil);
      //@ extract_key_at_index(nil, nil, nil, index, busybits_lst, key_opts);
      //@ append_nil(reverse(take(index, keys_lst)));
      //@ append_nil(reverse(take(index, busybits_lst)));
      //@ append_nil(reverse(take(index, key_opts)));
      //@ mul_bounds(key_size, key_size, index, real_capacity);
      //@ extract_object(keys_ptr, index);
      if (os_memory_eq(map->keys + (index * map->key_size), key_ptr, map->key_size)) {
        //@ stitch_objects(keys_ptr, index, real_capacity);
        //@ recover_key_opt_list(keys_lst, busybits_lst, key_opts, index);
        //@ key_opt_list_find_key(key_opts, index, key);
        map->busybits[index] = false;
        //@ rem_preserves_opt_no_dups(key_opts, index);
        //@ key_opts_rem_preserves_hash_list(key_opts, hashes_lst, index);
        //@ remove_decreases_key_opts_size(key_opts, index);
        //@ map_drop_key(index);
        //@ ghostmap_remove_when_distinct_and_present_decreases_length(items, key);
        //@ chns_after_partial_chain_ended(buckets, key, start, i, real_capacity);
        //@ buckets_remove_key_still_ok(buckets, key);
        //@ buckets_rm_key_get_keys(buckets, key);
        //@ buckets_remove_key_chains_still_start_on_hash(buckets, real_capacity, key);
        //@ buckets_remove_key_same_len(buckets, key);
        //@ close buckets_keys_insync(real_capacity, chains_lst, buckets_remove_key_fp(buckets, key), update(index_of(some(key), key_opts), none, key_opts));
        //@ close mapp2_core(real_capacity, keys_lst, _, hashes_lst, values_lst, _, ghostmap_remove(items, key));
        //@ drop_cons(keys_lst, index);
        //@ close mapp2(map, key_size, value_size, capacity, ghostmap_remove(items, key));
        return;
      }
      //@ stitch_objects(keys_ptr, index, real_capacity);
      //@ recover_key_opt_list(keys_lst, busybits_lst, key_opts, index);
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
    //@ close mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items);
    //@ drop_cons(keys_lst, index);
  }
  //@ open mapp2_core(real_capacity, keys_lst, busybits_lst, hashes_lst, values_lst, key_opts, items);
  //@ by_loop_for_all(key_opts, (neq)(some(key)), start, real_capacity, nat_of_int(real_capacity));
  //@ no_key_found(key_opts, key);
  //@ assert false;
}
