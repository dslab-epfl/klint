#include "structs/map.h"

#include "os/memory.h"

// This map was originally written by Arseniy Zaostrovnykh as part of the Vigor project,
// then optimized for the power-of-2-capacity case by Lucas Ramirez (since & is much cheaper than %).
// The proof was then adapted to use ghost-map-based contracts.
// Then, for performance, the implementation and proof were adapted to use array-of-structs rather than struct-of-arrays
// (since the former has much better cache behavior).
// Also, again for perf, the "busy bits" scheme was replaced with a "is key_addr NULL or not" scheme.
// VeriFast also improved in the meantime, meaning some workarounds in the original proof design
// may not be necessary any more, while some new workarounds are needed to e.g. support target-independent mode.
// The resulting code is neat, but to say the current proof is not pretty would be an understatement.
// Some thoughts on how to improve if this is ever rewritten:
// - Isolate stuff more. The proof currently takes forever because it has to look at tens of thousands of lines of proof.
// - See if any solver (e.g. Z3 or CVC4) is friendly to the mod-pow2 optimization, instead of manually proving bit tricks.
// - Remove the intermediate "key_opts" layer between the raw map and the ghost maps, it's a historical artifact
// - Consider using forall_, it sometimes works very well.
// - Avoid using the 'nat' type, it's just annoying to use
// - Redo the proof/... structuring, right now all kinds of lemmas are in all kinds of places due to refactorings

//@ #include "proof/chain-buckets.gh"
//@ #include "proof/listexex.gh"
//@ #include "proof/modulo.gh"
//@ #include "proof/mod-pow2.gh"
//@ #include "proof/nth-prop.gh"
//@ #include "proof/stdex.gh"

struct map_item {
	void* key_addr;
	size_t value;
	size_t chain;
	hash_t key_hash;
	uint32_t _padding;
} __attribute__((packed));

// VeriFast defines NULL as just 0 and then complains types don't match
#undef NULL
#define NULL ((void*)0)

/*@
  inductive map_item = map_item(void*, size_t, size_t, hash_t);

  fixpoint void* map_item_key_addr_(map_item item) { switch(item) { case map_item(key_addr, value, chain, key_hash): return key_addr; } }
  fixpoint size_t map_item_value_(map_item item) { switch(item) { case map_item(key_addr, value, chain, key_hash): return value; } }
  fixpoint size_t map_item_chain_(map_item item) { switch(item) { case map_item(key_addr, value, chain, key_hash): return chain; } }
  fixpoint hash_t map_item_key_hash_(map_item item) { switch(item) { case map_item(key_addr, value, chain, key_hash): return key_hash; } }

  predicate map_itemp(struct map_item* ptr; map_item item) =
    ptr->key_addr |-> ?key_addr &*&
    ptr->value |-> ?value &*&
    ptr->chain |-> ?chain &*&
    ptr->key_hash |-> ?key_hash &*&
    ptr->_padding |-> ?_padding &*&
    item == map_item(key_addr, value, chain, key_hash);

  predicate map_itemsp(struct map_item* ptr, size_t count; list<map_item> items) =
      count == 0 ?
        items == nil
      :
        map_itemp(ptr, ?item) &*& map_itemsp(ptr + 1, count - 1, ?items_tail) &*&
        items == cons(item, items_tail);

  lemma void length_map_items(size_t count)
    requires map_itemsp(?ptr, count, ?items);
    ensures map_itemsp(ptr, count, items) &*&
            length(items) == count;
  {
    open map_itemsp(ptr, count, items);
    switch (items) {
      case nil:
      case cons(h, t):
        length_map_items(count - 1);
    }
    close map_itemsp(ptr, count, items);
  }

  lemma void bytes_to_map_item(char* ptr)
    requires chars(ptr, sizeof(struct map_item), ?cs) &*&
             true == all_eq(cs, 0);
    ensures map_itemp((struct map_item*) ptr, ?i) &*&
            i == map_item(?ka, ?va, ?ch, ?ha) &*&
            ch == 0 &*&
            ka == NULL;
  {
    struct map_item* mip = (struct map_item*) ptr;
    chars_split(ptr, sizeof(void*));
    chars_to_pointer((void*) &(mip->key_addr));
    assume(mip->key_addr == NULL); // VeriFast's chars-to-integers loses track of the value, but we have all chars == 0 as a precondition
    chars_split(ptr + sizeof(void*), sizeof(size_t));
    chars_to_integer_((void*) &(mip->value), sizeof(size_t), false);
    chars_split(ptr + sizeof(void*) + sizeof(size_t), sizeof(size_t));
    chars_to_integer_((void*) &(mip->chain), sizeof(size_t), false);
    assume(mip->chain == 0); // VeriFast's chars-to-integers loses track of the value, but we have all chars == 0 as a precondition
    chars_split(ptr + sizeof(void*) + sizeof(size_t) + sizeof(size_t), sizeof(hash_t));
    chars_to_integer_((void*) &(mip->key_hash), sizeof(hash_t), false);
    chars_split(ptr + sizeof(void*) + sizeof(size_t) + sizeof(size_t) + sizeof(hash_t), sizeof(uint32_t));
    chars_to_integer_((void*) &(mip->_padding), sizeof(uint32_t), false);
    close map_itemp(mip, _);
  }

  lemma void all_eq_append<t>(list<t> xs1, list<t> xs2, t x)
    requires emp;
    ensures all_eq(append(xs1, xs2), x) == (all_eq(xs1, x) && all_eq(xs2, x));
  {
    switch (xs1) {
      case nil:
      case cons(xs1h, xs1t):
        all_eq_append(xs1t, xs2, x);
    }
  }

  lemma void bytes_to_map_items(char* ptr, nat count)
    requires chars(ptr, int_of_nat(count) * sizeof(struct map_item), ?cs) &*&
             true == all_eq(cs, 0);
    ensures map_itemsp((struct map_item*) ptr, int_of_nat(count), ?is) &*&
            true == forall(map(map_item_chain_, is), (eq)(0)) &*&
            true == forall(map(map_item_key_addr_, is), (eq)(NULL));
  {
    switch (count) {
      case zero:
        close map_itemsp((struct map_item*) ptr, 0, nil);
      case succ(next):
        mul_mono(1, int_of_nat(count), sizeof(struct map_item));
        chars_split(ptr, sizeof(struct map_item));
        all_eq_append(take(sizeof(struct map_item), cs), drop(sizeof(struct map_item), cs), 0);
        mul_subst(int_of_nat(count)-1, int_of_nat(next), sizeof(struct map_item));
        bytes_to_map_items(ptr + sizeof(struct map_item), next);
        bytes_to_map_item(ptr);
        close map_itemsp((struct map_item*) ptr, int_of_nat(count), _);
    }
  }

lemma void extract_item(struct map_item* ptr, size_t i)
  requires map_itemsp(ptr, ?count, ?items) &*&
           0 <= i &*& i < count;
  ensures map_itemsp(ptr, i, take(i, items)) &*&
          map_itemp(ptr + i, nth(i, items)) &*&
          map_itemsp(ptr + i + 1, count - i - 1, drop(i+1, items));
  {
    open map_itemsp(ptr, count, items);
    switch(items) {
      case nil:
      case cons(h, t):
        if (i != 0) {
          extract_item(ptr + 1, i - 1);
        }
    }
    close map_itemsp(ptr, i, take(i, items));
  }

  lemma void glue_items(struct map_item* ptr, list<map_item> items, int i)
  requires 0 <= i &*& i < length(items) &*&
           map_itemsp(ptr, i, take(i, items)) &*&
           map_itemp(ptr + i, nth(i, items)) &*&
           map_itemsp(ptr + i + 1, length(items) - i - 1, drop(i + 1, items));
  ensures map_itemsp(ptr, length(items), items);
  {
    switch(items) {
      case nil:
      case cons(h,t):
        open map_itemsp(ptr, i, take(i, items));
        if (i == 0) {
        } else {
          glue_items(ptr + 1, t, i-1);
        }
        close map_itemsp(ptr, length(items), items);
    }
  }
@*/

struct map {
	struct map_item* items;
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

  // Addresses => key options
  predicate key_opt_list(size_t key_size, list<void*> kaddrs;
                         list<option<list<char> > > key_opts) =
    switch(kaddrs) {
      case nil:
        return key_opts == nil;
      case cons(kaddrsh, kaddrst):
        return key_opt_list(key_size, kaddrst, ?key_optst) &*&
               kaddrsh == NULL ? (key_opts == cons(none, key_optst)) : ([0.25]chars(kaddrsh, key_size, ?key_optsh) &*& key_opts == cons(some(key_optsh), key_optst));
    };

  // Key options => hashes
  // NOTE: It's important that we say nothing about hashes of none keys, which is why this can't return a list of hashes (which would need to reason about this info)
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
  predicate buckets_keys_insync(size_t capacity, list<size_t> chains, list<bucket<list<char> > > buckets;
                                list<option<list<char> > > key_opts) =
    chains == buckets_get_chns_fp(buckets) &*&
    true == buckets_ok(buckets) &*&
    true == key_chains_start_on_hash_fp(buckets, 0, capacity) &*&
    key_opts == buckets_get_keys_fp(buckets) &*&
    length(buckets) == capacity;

  // Partial: Chains + buckets => key options
  predicate buckets_keys_insync_Xchain(size_t capacity, list<size_t> chains, list<bucket<list<char> > > buckets, size_t start, size_t fin; list<option<list<char> > > key_opts) =
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
  predicate map_valuesaddrs(list<void*> kaddrs, list<option<list<char> > > key_opts, list<size_t> values,
                            list<pair<list<char>, size_t> > map_values, list<pair<list<char>, void*> > map_addrs) =
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

  // Keys + hashes + values => key options + map values + map addresses
  predicate mapp_core(size_t key_size, size_t capacity,
                      list<void*> kaddrs, list<hash_t> hashes, list<size_t> values,
                      list<option<list<char> > > key_opts, list<pair<list<char>, size_t> > map_values, list<pair<list<char>, void*> > map_addrs) =
     key_opt_list(key_size, kaddrs, key_opts) &*&
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
  predicate mapp_raw(struct map* m; list<void*> kaddrs, list<hash_t> hashes, list<size_t> chains, list<size_t> values, size_t key_size, size_t capacity) =
    struct_map_padding(m) &*&
    m->key_size |-> key_size &*&
    m->capacity |-> capacity &*&
    m->items |-> ?raw_items &*&
    map_itemsp(raw_items, capacity, ?items) &*&
    kaddrs == map(map_item_key_addr_, items) &*&
    hashes == map(map_item_key_hash_, items) &*&
    values == map(map_item_value_, items) &*&
    chains == map(map_item_chain_, items) &*&
    capacity == length(items) &*&
    capacity == length(kaddrs) &*&
    capacity == length(hashes) &*&
    capacity == length(values) &*&
    capacity == length(chains);

  // Combine everything, including the chains optimization
  predicate mapp(struct map* map, size_t key_size, size_t capacity, list<pair<list<char>, size_t> > map_values, list<pair<list<char>, void*> > map_addrs) =
    mapp_raw(map, ?kaddrs, ?hashes, ?chains, ?values, key_size, ?real_capacity) &*&
    mapp_core(key_size, real_capacity, kaddrs, hashes, values, ?key_opts, map_values, map_addrs) &*&
    buckets_keys_insync(real_capacity, chains, ?buckets, key_opts) &*&
    capacity == 0 ? real_capacity == 0
                  : (real_capacity >= capacity &*&
                     real_capacity <= SIZE_MAX / 2 + 1 &*&
                     is_pow2(real_capacity, N63) != none);
@*/

static size_t get_real_capacity(size_t capacity)
//@ requires capacity <= SIZE_MAX / 2 + 1;
/*@ ensures capacity == 0 ? result == 0 :
                            (result >= capacity &*&
                             result <= capacity * 2 &*&
                             is_pow2(result, N63) != none); @*/
//@ terminates;
{
  if (capacity == 0) {
    return 0;
  }
  size_t real_capacity = 1;
  while (real_capacity < capacity)
  /*@ invariant is_pow2(real_capacity, N63) != none &*&
                real_capacity <= capacity * 2; @*/
  //@ decreases SIZE_MAX - real_capacity;
  {
    //@ mul_mono(real_capacity, SIZE_MAX / 2, 2);
    //@ div_exact_rev(SIZE_MAX, 2);
    real_capacity *= 2;
  }
  //@ assert none != is_pow2(real_capacity, N63);
  return real_capacity;
}

static size_t loop(hash_t start, size_t i, size_t capacity)
/*@ requires i < capacity &*&
             capacity <= SIZE_MAX / 2 + 1 &*&
             is_pow2(capacity, N63) != none; @*/
/*@ ensures 0 <= result &*& result < capacity &*&
            result == loop_fp(start + i, capacity) &*&
            0 <= loop_fp(start, capacity) &*& loop_fp(start, capacity) < capacity &*&
            result == loop_fp(loop_fp(start, capacity) + i, capacity); @*/
//@ terminates;
{
  // Here we'd like to eliminate the first AND.
  // However, this would require proving to VeriFast that (start + i) cannot overflow,
  // which is false on some architectures (e.g. 'int' can be 4 bytes and 'size_t' 2 bytes, in theory)
  // So let's just hope the compiler does it for us...

  //@ nat m = is_pow2_some(capacity, N63);
  //@ mod_bitand_equiv(start, capacity, m);
  //@ div_mod_gt_0(start % capacity, start, capacity);
  size_t startmod = (size_t) start & (capacity - 1);
  //@ mod_bitand_equiv(startmod + i, capacity, m);
  //@ div_mod_gt_0((startmod + i) % capacity, startmod + i, capacity);
  //@ mod_mod(start, i, capacity);
  //@ div_exact_rev(SIZE_MAX, 2);
  return (startmod + i) & (capacity - 1);
}

/*@
lemma void extend_repeat_n<t>(nat len, t extra, t z)
  requires emp;
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
  requires emp;
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
  requires length(hashes) == length(kaddrs) &*&
           true == forall(kaddrs, (eq)(NULL));
  ensures key_opt_list(key_size, kaddrs, repeat_n(nat_of_int(length(kaddrs)), none)) &*&
          length(kaddrs) == length(repeat_n(nat_of_int(length(kaddrs)), none));
{
  switch(kaddrs) {
    case nil:
      close key_opt_list(key_size, kaddrs, repeat_n(nat_of_int(length(kaddrs)), none));
    case cons(kaddrh,kaddrt):
      switch(hashes) {
        case nil:
        case cons(hh,ht):
      }
      produce_key_opt_list(key_size, tail(hashes), kaddrt);
      nat_len_of_non_nil(kaddrh,kaddrt);
      close key_opt_list(key_size, kaddrs, repeat_n(nat_of_int(length(kaddrs)), none));
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

lemma void forall_eq_to_repeat_n<t>(list<t> items, t value)
  requires true == forall(items, (eq)(value));
  ensures items == repeat_n(nat_of_int(length(items)), value);
{
  switch(items) {
    case nil:
    case cons(h, t):
      forall_eq_to_repeat_n(t, value);
      assert t == repeat_n(nat_of_int(length(t)), value);
      assert h == value;
      assert cons(h, t) == repeat_n(succ(nat_of_int(length(t))), value);
      assert cons(h, t) == repeat_n(nat_of_int(length(t)+1), value);
      assert cons(h, t) == repeat_n(nat_of_int(length(items)), value);
      assert items == repeat_n(nat_of_int(length(items)), value);
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

lemma void produce_empty_map_valuesaddrs(size_t capacity, list<void*> kaddrs, list<size_t> values)
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

struct map* map_alloc(size_t key_size, size_t capacity)
/*@ requires capacity * 64 <= SIZE_MAX; @*/
/*@ ensures mapp(result, key_size, capacity, nil, nil); @*/
//@ terminates;
{
  // NOTE: Technically, the 'requires' only needs to use 32 (= sizeof(struct map_item)), not 64, but that'd require proving that real_capacity == capacity in that case
  struct map* m = (struct map*) os_memory_alloc(1, sizeof(struct map));
  //@ close_struct_zero(m);
  //@ div_ge(capacity * 32, SIZE_MAX + 2, 2);
  //@ div_2_plus_2(SIZE_MAX);
  //@ div_even(capacity, 32);
  size_t real_capacity = get_real_capacity(capacity);
  m->items = (struct map_item*) os_memory_alloc(real_capacity, sizeof(struct map_item));
  m->capacity = real_capacity;
  m->key_size = key_size;
  //@ assert m->items |-> ?raw_items;
  //@ bytes_to_map_items((char*) raw_items, nat_of_int(real_capacity));
  //@ assert map_itemsp(raw_items, real_capacity, ?items);
  //@ length_map_items(real_capacity);
  //@ map_preserves_length(map_item_key_addr_, items);
  //@ map_preserves_length(map_item_value_, items);
  //@ map_preserves_length(map_item_chain_, items);
  //@ map_preserves_length(map_item_key_hash_, items);
  //@ list<void*> kaddrs_lst = map(map_item_key_addr_, items);
  //@ list<hash_t> hashes_lst = map(map_item_key_hash_, items);
  //@ list<size_t> chains_lst = map(map_item_chain_, items);
  //@ list<size_t> values_lst = map(map_item_value_, items);
  //@ close mapp_raw(m, kaddrs_lst, hashes_lst, chains_lst, values_lst, key_size, real_capacity);
  //@ repeat_n_contents(nat_of_int(real_capacity), false);
  //@ produce_key_opt_list(key_size, hashes_lst, kaddrs_lst);
  //@ assert key_opt_list(key_size, kaddrs_lst, ?kopts);
  //@ repeat_n_contents(nat_of_int(real_capacity), none);
  //@ kopts_size_0_when_empty(kopts);
  //@ forall_eq_to_repeat_n(chains_lst, 0);
  //@ assert chains_lst == repeat_n(nat_of_int(length(kaddrs_lst)), 0);
  //@ empty_buckets_insync(chains_lst, real_capacity);
  //@ produce_empty_map_valuesaddrs(real_capacity, kaddrs_lst, values_lst);
  //@ produce_empty_hash_list(kopts, hashes_lst);
  //@ repeat_none_is_opt_no_dups(nat_of_int(real_capacity), kopts);
  //@ close mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, kopts, nil, nil);
  //@ close mapp(m, key_size, capacity, nil, nil);
  return m;
}


/*@
lemma list<char> extract_key_at_index(list<void*> kaddrs_b, list<option<list<char> > > key_opts_b, size_t n,
                                      list<void*> kaddrs, list<option<list<char> > > key_opts)
  requires key_opt_list(?key_size, kaddrs, key_opts) &*&
           key_opt_list(key_size, kaddrs_b, key_opts_b) &*&
           0 <= n &*& n < length(kaddrs) &*& NULL != nth(n, kaddrs);
  ensures nth(n, key_opts) == some(result) &*& [0.25]chars(nth(n, kaddrs), key_size, result) &*&
          key_opt_list(key_size, drop(n+1, kaddrs), drop(n+1, key_opts)) &*&
          key_opt_list(key_size,
                       append(reverse(take(n, kaddrs)), kaddrs_b),
                       append(reverse(take(n, key_opts)), key_opts_b));
{
  open key_opt_list(_, kaddrs, _);
      switch(kaddrs) {
        case nil:
        case cons(kph, kpt):
          switch(key_opts) {
            case nil:
            case cons(kh, kt):
            if (n == 0) {
              switch(kh) {
                case some(k):
                  return k;
                case none:
              }
            } else {
              close key_opt_list(key_size, cons(kph, kaddrs_b), cons(kh, key_opts_b));
              append_reverse_take_cons(n,kph,kpt,kaddrs_b);
              append_reverse_take_cons(n,kh,kt,key_opts_b);
              return extract_key_at_index(cons(kph,kaddrs_b),
                                          cons(kh, key_opts_b),
                                          n-1, kpt, kt);
            }
          }
  }
}

// ---

lemma void reconstruct_key_opt_list(list<void*> kaddrs1,
                                    list<void*> kaddrs2)
  requires key_opt_list(?key_size, kaddrs1, ?key_opts1) &*&
           key_opt_list(key_size, kaddrs2, ?key_opts2);
  ensures key_opt_list(key_size,
                       append(reverse(kaddrs1), kaddrs2),
                       append(reverse(key_opts1), key_opts2));
{
  open key_opt_list(key_size, kaddrs1, key_opts1);
  switch(kaddrs1) {
    case nil:
      assert(key_opts1 == nil);
    case cons(ka1h, ka1t):
      append_reverse_tail_cons_head(kaddrs1, kaddrs2);
      append_reverse_tail_cons_head(key_opts1, key_opts2);
      assert key_opts1 == cons(?ko1h, _);
      close key_opt_list(key_size, cons(ka1h, kaddrs2), cons(ko1h, key_opts2));
      reconstruct_key_opt_list(ka1t, cons(ka1h, kaddrs2));
  }
}

lemma void recover_key_opt_list(list<void*> kaddrs, list<option<list<char> > > key_opts, size_t n)
  requires key_opt_list(?key_size, reverse(take(n, kaddrs)), reverse(take(n, key_opts))) &*&
           NULL != nth(n, kaddrs) &*&
           [0.25]chars(nth(n, kaddrs), key_size, ?k) &*&
           nth(n, key_opts) == some(k) &*&
           key_opt_list(key_size, drop(n+1, kaddrs), drop(n+1, key_opts)) &*&
           0 <= n &*& n < length(kaddrs) &*&
           n < length(key_opts);
  ensures key_opt_list(key_size, kaddrs, key_opts);
{
  close key_opt_list(key_size,
                     cons(nth(n, kaddrs), drop(n+1,kaddrs)),
                     cons(nth(n, key_opts), drop(n+1, key_opts)));
  drop_n_plus_one(n, kaddrs);
  drop_n_plus_one(n, key_opts);
  reconstruct_key_opt_list(reverse(take(n, kaddrs)),
                           drop(n, kaddrs));
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
    case cons(kh,kt):
      assert hashes == cons(?hh, ?ht);
      if (i == 0) {
        assert nth(i, key_opts) == kh;
        if (kh == some(k)) {
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

lemma void no_bb_no_key(list<option<list<char> > > key_opts, list<void*> kaddrs, size_t i)
  requires key_opt_list(?key_size, kaddrs, key_opts) &*& 0 <= i &*& i < length(key_opts) &*&
           NULL == nth(i, kaddrs);
  ensures key_opt_list(key_size, kaddrs, key_opts) &*& nth(i, key_opts) == none;
{
  open key_opt_list(key_size, kaddrs, key_opts);
  switch(kaddrs) {
    case nil:
    case cons(kaddrsh,kaddrst):
      if (i == 0) {
        nth_0_head(kaddrs);
        nth_0_head(key_opts);
      } else {
        no_bb_no_key(tail(key_opts), kaddrst, i-1);
      }
  }
  close key_opt_list(key_size, kaddrs, key_opts);
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
  }
  close map_valuesaddrs(kaddrs, key_opts, values, map_values, map_addrs);
}
@*/

bool map_get(struct map* map, void* key_ptr, size_t* out_value)
/*@ requires mapp(map, ?key_size, ?capacity, ?map_values, ?map_addrs) &*&
             key_ptr != NULL &*&
             [?frac]chars(key_ptr, key_size, ?key) &*&
             *out_value |-> _; @*/
/*@ ensures mapp(map, key_size, capacity, map_values, map_addrs) &*&
            [frac]chars(key_ptr, key_size, key) &*&
            switch(ghostmap_get(map_values, key)) {
              case none: return result == false &*& *out_value |-> _;
              case some(v): return result == true &*& *out_value |-> v;
            }; @*/
//@ terminates;
{
  //@ open mapp(map, key_size, capacity, map_values, map_addrs);
  hash_t key_hash = os_memory_hash(key_ptr, map->key_size);
  for (size_t i = 0; i < map->capacity; ++i)
    /*@ invariant mapp_raw(map, ?kaddrs_lst, ?hashes_lst, ?chains_lst, ?values_lst, key_size, ?real_capacity) &*&
                  mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, ?key_opts, map_values, map_addrs) &*&
                  buckets_keys_insync(real_capacity, chains_lst, ?buckets, key_opts) &*&
                  0 <= i &*& i <= real_capacity &*&
                  [frac]chars(key_ptr, key_size, key) &*&
                  hash_fp(key) == key_hash &*&
                  capacity == 0 ? real_capacity == 0 :
                                  (real_capacity >= capacity &*&
                                   real_capacity <= SIZE_MAX / 2 + 1 &*&
                                   is_pow2(real_capacity, N63) != none) &*&
                  true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, loop_fp(key_hash, real_capacity))) &*&
                  *out_value |-> _; @*/
  //@ decreases real_capacity - i;
  {
    //@ open mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
    //@ open buckets_keys_insync(real_capacity, chains_lst, buckets, key_opts);
    size_t index = loop(key_hash, i, map->capacity);
    struct map_item* it = &(map->items[index]);
    //@ assert map->items |-> ?raw_items;
    //@ assert map_itemsp(raw_items, real_capacity, ?the_items);
    //@ extract_item(raw_items, index);
    if (it->key_addr != NULL && it->key_hash == key_hash) {
      //@ close key_opt_list(key_size, nil, nil);
      //@ assert nth(index, kaddrs_lst) == nth(index, map(map_item_key_addr_, the_items));
      //@ nth_map(index, map_item_key_addr_, the_items);
      //@ extract_key_at_index(nil, nil, index, kaddrs_lst, key_opts);
      //@ append_nil(reverse(take(index, kaddrs_lst)));
      //@ append_nil(reverse(take(index, key_opts)));
      //@ nth_map(index, map_item_key_addr_, the_items);
      if (os_memory_eq(it->key_addr, key_ptr, map->key_size)) {
        //@ recover_key_opt_list(kaddrs_lst, key_opts, index);
        //@ open map_valuesaddrs(kaddrs_lst, key_opts, values_lst, map_values, map_addrs);
        //@ assert true == opt_no_dups(key_opts);
        //@ close map_valuesaddrs(kaddrs_lst, key_opts, values_lst, map_values, map_addrs);
        //@ key_opt_list_find_key(key_opts, index, key);
        //@ close buckets_keys_insync(real_capacity, chains_lst, buckets, key_opts);
        //@ map_values_reflects_keyopts_mem(key, index);
        //@ nth_map(index, map_item_value_, the_items);
        *out_value = it->value;
        //@ close mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
        //@ glue_items(raw_items, the_items, index);
        //@ close mapp_raw(map, kaddrs_lst, hashes_lst, chains_lst, values_lst, key_size, real_capacity);
        //@ close mapp(map, key_size, capacity, map_values, map_addrs);
        return true;
      }
      //@ recover_key_opt_list(kaddrs_lst, key_opts, index);
    } else {
      //@ nth_map(index, map_item_key_addr_, the_items);
      //@ nth_map(index, map_item_key_hash_, the_items);
      //@ if (NULL == nth(index, map(map_item_key_addr_, the_items))) no_bb_no_key(key_opts, kaddrs_lst, index); else no_hash_no_key(key_opts, hashes_lst, key, index);
      if (it->chain == 0) {
        //@ assert length(chains_lst) == real_capacity;
        //@ buckets_keys_chns_same_len(buckets);
        //@ assert length(buckets) == real_capacity;
        //@ nth_map(index, map_item_chain_, the_items);
        //@ no_crossing_chains_here(buckets, index);
        //@ assert nil == get_crossing_chains_fp(buckets, index);
        //@ key_is_contained_in_the_bucket(buckets, real_capacity, key);
        //@ assert true == up_to(nat_of_int(i), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, loop_fp(hash_fp(key), real_capacity)));
        //@ assert true == up_to(succ(nat_of_int(i)), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, loop_fp(hash_fp(key), real_capacity)));
        //@ assert true == up_to(nat_of_int(i+1), (byLoopNthProp)(key_opts, (neq)(some(key)), real_capacity, loop_fp(hash_fp(key), real_capacity)));
        //@ assert buckets != nil;
        //@ chains_depleted_no_hope(buckets, i, loop_fp(hash_fp(key), real_capacity), key, real_capacity);
        //@ assert false == mem(some(key), key_opts);
        //@ key_opts_has_not_implies_map_values_has_not(key);
        //@ close buckets_keys_insync(real_capacity, chains_lst, buckets, key_opts);
        //@ close mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
        //@ glue_items(raw_items, the_items, index);
        //@ close mapp_raw(map, kaddrs_lst, hashes_lst, chains_lst, values_lst, key_size, real_capacity);
        //@ close mapp(map, key_size, capacity, map_values, map_addrs);
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
    //@ close mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
    //@ glue_items(raw_items, the_items, index);
  }
  //@ open mapp_core(key_size, ?real_capacity, ?kaddrs_lst, ?hashes_lst, ?values_lst, ?key_opts, map_values, map_addrs);
  //@ assert buckets_keys_insync(real_capacity, ?chains_lst, ?buckets, key_opts);
  /*@ if (real_capacity != 0) {
        loop_lims(key_hash, real_capacity);
        by_loop_for_all(key_opts, (neq)(some(key)), loop_fp(key_hash, real_capacity), real_capacity, nat_of_int(real_capacity));
      } @*/
  //@ no_key_found(key_opts, key);
  //@ key_opts_has_not_implies_map_values_has_not(key);
  //@ close mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
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

lemma void zero_bbs_is_for_empty(list<void*> kaddrs, list<option<list<char> > > key_opts, size_t i)
  requires key_opt_list(?key_size, kaddrs, key_opts) &*&
           NULL == nth(i, kaddrs) &*&
           0 <= i &*& i < length(kaddrs);
  ensures key_opt_list(key_size, kaddrs, key_opts) &*&
          nth(i, key_opts) == none &*&
          opts_size(key_opts) < length(key_opts);
{
  open key_opt_list(key_size, kaddrs, key_opts);
  switch(kaddrs) {
    case nil:
    case cons(h,t):
      if (i == 0) {
        key_opts_size_limits(tail(key_opts));
      } else {
        nth_cons(i, t, h);
        zero_bbs_is_for_empty(t, tail(key_opts), i-1);
      }
  }
  close key_opt_list(key_size, kaddrs, key_opts);
}

// ---

lemma void start_Xchain(size_t capacity, list<size_t> chains,  list<bucket<list<char> > > buckets, list<option<list<char> > > key_opts, size_t start)
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

lemma void bb_nonzero_cell_busy(list<void*> kaddrs, list<option<list<char> > > key_opts, size_t i)
  requires key_opt_list(?key_size, kaddrs, key_opts) &*&
           NULL != nth(i, kaddrs) &*&
           0 <= i &*& i < length(kaddrs);
  ensures key_opt_list(key_size, kaddrs, key_opts) &*&
          true == cell_busy(nth(i, key_opts));
  {
    open key_opt_list(key_size, kaddrs, key_opts);
    switch(kaddrs) {
      case nil:
      case cons(h,t):
      if (i == 0) {
      } else {
        nth_cons(i, t, h);
        bb_nonzero_cell_busy(t, tail(key_opts), i-1);
      }
    }
    close key_opt_list(key_size, kaddrs, key_opts);
  }

// ---

lemma void put_keeps_key_opt_list(list<void*> kaddrs, list<option<list<char> > > key_opts, int index, void* key, list<char> k)
  requires key_opt_list(?key_size, kaddrs, key_opts) &*&
           key != NULL &*&
           [0.25]chars(key, key_size, k) &*&
           0 <= index &*& index < length(kaddrs) &*&
           nth(index, key_opts) == none;
  ensures key_opt_list(key_size, update(index, key, kaddrs), update(index, some(k), key_opts));
{
  open key_opt_list(key_size, kaddrs, key_opts);
  switch(kaddrs) {
    case nil:
    case cons(kah, kat):
      assert key_opts == cons(?koh, ?kot);
      if (index == 0) {
        tail_of_update_0(kaddrs, key);
        tail_of_update_0(key_opts, some(k));
        head_update_0(key, kaddrs);
      } else {
        put_keeps_key_opt_list(kat, kot, index-1, key, k);
        cons_head_tail(kaddrs);
        cons_head_tail(key_opts);
        update_tail_tail_update(kah, kat, index, key);
        update_tail_tail_update(koh, kot, index, some(k));
      }
      update_non_nil(kaddrs, index, key);
      update_non_nil(key_opts, index, some(k));
  }
  close key_opt_list(key_size, update(index, key, kaddrs), update(index, some(k), key_opts));
}

// ---

lemma void map_values_has_not_implies_key_opts_has_not(list<pair<list<char>, size_t> > map_values, list<option<list<char> > > key_opts, list<char> key)
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

lemma void put_updates_valuesaddrs(size_t index, void* key_ptr, list<char> key, size_t value)
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
      if (index != 0) {
        put_updates_valuesaddrs(index - 1, key_ptr, key, value);
      }
      ghostmap_set_preserves_distinct(map_values, key, value);
      ghostmap_set_preserves_distinct(map_addrs, key, key_ptr);
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

// ---

lemma void map_nth_nth_map<a, b>(fixpoint(a, b) fp, int index, list<a> lst)
requires 0 <= index &*& index < length(lst);
ensures fp(nth(index, lst)) == nth(index, map(fp, lst));
{
  switch(lst) {
    case nil:
    case cons(h, t):
      if (index != 0) {
        map_nth_nth_map(fp, index - 1, t);
      }
  }
}

// ---

lemma void map_update_update_map<a, b>(fixpoint(a, b) fp, int index, a item, list<a> lst)
requires 0 <= index &*& index < length(lst);
ensures map(fp, update(index, item, lst)) == update(index, fp(item), map(fp, lst));
{
  switch(lst) {
    case nil:
    case cons(h, t):
      if (index != 0) {
        map_update_update_map(fp, index - 1, item, t);
      }
  }
}

// ---

lemma void size_wtf(size_t a, size_t b)
requires a <= SIZE_MAX / 2 &*& b <= SIZE_MAX / 2;
ensures a + b <= SIZE_MAX;
{
    div_exact_rev(SIZE_MAX, 2);
}
@*/

void map_set(struct map* map, void* key_ptr, size_t value)
/*@ requires mapp(map, ?key_size, ?capacity, ?map_values, ?map_addrs) &*&
             key_ptr != NULL &*&
             [0.25]chars(key_ptr, key_size, ?key) &*&
             length(map_values) < capacity &*&
             ghostmap_get(map_values, key) == none &*&
             ghostmap_get(map_addrs, key) == none; @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_set(map_values, key, value), ghostmap_set(map_addrs, key, key_ptr)); @*/
//@ terminates;
{
  //@ open mapp(map, key_size, capacity, map_values, map_addrs);
  hash_t key_hash = os_memory_hash(key_ptr, map->key_size);
  //@ assert buckets_keys_insync(?real_capacity, ?old_chains_lst, ?buckets, ?key_opts);
  //@ size_t start = loop_fp(key_hash, real_capacity);
  //@ loop_lims(key_hash, real_capacity);
  //@ start_Xchain(real_capacity, old_chains_lst, buckets, key_opts, start);
  //@ loop_bijection(start, real_capacity);
  for (size_t i = 0; i < map->capacity; ++i)
    /*@ invariant mapp_raw(map, ?kaddrs_lst, ?hashes_lst, ?chains_lst, ?values_lst, key_size, real_capacity) &*&
                  mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs) &*&
                  is_pow2(real_capacity, N63) != none &*&
                  key_ptr != NULL &*&
                  [0.25]chars(key_ptr, key_size, key) &*&
                  0 <= i &*& i <= real_capacity &*&
                  true == up_to(nat_of_int(i),(byLoopNthProp)(key_opts, cell_busy, real_capacity, start)) &*&
                  buckets_keys_insync_Xchain(real_capacity, chains_lst, buckets, start, loop_fp(start + i, real_capacity), key_opts); @*/
  //@ decreases real_capacity - i;
  {
    size_t index = loop(key_hash, i, map->capacity);
    //@ open mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
    //@ open buckets_keys_insync_Xchain(real_capacity, chains_lst, buckets, start, index, key_opts);
    struct map_item* item = &(map->items[index]);
    //@ assert map->items |-> ?raw_items;
    //@ assert map_itemsp(raw_items, real_capacity, ?the_items);
    //@ extract_item(raw_items, index);
    if (item->key_addr == NULL) {
      //@ nth_map(index, map_item_key_addr_, the_items);
      //@ zero_bbs_is_for_empty(kaddrs_lst, key_opts, index);
      //@ map_values_has_not_implies_key_opts_has_not(map_values, key_opts, key);
      item->key_addr = key_ptr;
      item->key_hash = key_hash;
      item->value = value;
      //@ no_key_in_ks_no_key_in_buckets(buckets, key);
      //@ close buckets_keys_insync_Xchain(real_capacity, chains_lst, buckets, start, index, key_opts);
      //@ buckets_keys_put_key_insync(real_capacity, chains_lst, start, index, key, key_opts);
      //@ put_keeps_key_opt_list(kaddrs_lst, key_opts, index, key_ptr, key);
      //@ put_updates_valuesaddrs(index, key_ptr, key, value);
      //@ put_preserves_no_dups(key_opts, index, key);
      //@ put_preserves_hash_list(key_opts, hashes_lst, index, key, key_hash);
      //@ put_increases_key_opts_size(key_opts, index, key);
      //@ ghostmap_set_preserves_distinct(map_values, key, value);
      //@ ghostmap_set_preserves_distinct(map_addrs, key, key_ptr);
      //@ assert true == ghostmap_distinct(ghostmap_set(map_values, key, value));
      //@ close mapp_core(key_size, real_capacity, ?new_kaddrs_lst, ?new_hashes_lst, ?new_values_lst, ?new_key_opts, ?new_map_values, ?new_map_addrs);
      //@ map_item new_item = map_item(key_ptr, value, map_item_chain_(nth(index, the_items)), key_hash);
      //@ take_update_unrelevant(index, index, new_item, the_items);
      //@ drop_update_unrelevant(index + 1, index, new_item, the_items);
      //@ map_preserves_length(map_item_key_addr_, update(index, new_item, the_items));
      //@ map_preserves_length(map_item_value_, update(index, new_item, the_items));
      //@ map_preserves_length(map_item_chain_, update(index, new_item, the_items));
      //@ map_preserves_length(map_item_key_hash_, update(index, new_item, the_items));
      //@ map_update_update_map(map_item_key_addr_, index, new_item, the_items);
      //@ map_update_update_map(map_item_value_, index, new_item, the_items);
      //@ map_update_update_map(map_item_chain_, index, new_item, the_items);
      //@ map_update_update_map(map_item_key_hash_, index, new_item, the_items);
      //@ map_nth_nth_map(map_item_chain_, index, the_items);
      //@ glue_items(raw_items, update(index, new_item, the_items), index);
      //@ close mapp(map, key_size, capacity, new_map_values, new_map_addrs);
      return;
    }
    //@ buckets_keys_chns_same_len(buckets);
    //@ buckets_ok_chn_bound(buckets, index);
    //@ outside_part_chn_no_effect(buckets_get_chns_fp(buckets), start, index, real_capacity);
    //@ assert item->chain |-> ?chn;
    //@ nth_map(index, map_item_chain_, the_items);
    //@ div_ge(4, SIZE_MAX, 2);
    //@ size_wtf(SIZE_MAX / 2, 2);
    item->chain = item->chain + 1;
    //@ nth_map(index, map_item_key_addr_, the_items);
    //@ bb_nonzero_cell_busy(kaddrs_lst, key_opts, index);
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
    //@ close mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
    //@ map_item new_item = map_item(map_item_key_addr_(nth(index, the_items)), map_item_value_(nth(index, the_items)), 1 + map_item_chain_(nth(index, the_items)), map_item_key_hash_(nth(index, the_items)));
    //@ take_update_unrelevant(index, index, new_item, the_items);
    //@ drop_update_unrelevant(index + 1, index, new_item, the_items);
    //@ map_preserves_length(map_item_key_addr_, update(index, new_item, the_items));
    //@ map_preserves_length(map_item_value_, update(index, new_item, the_items));
    //@ map_preserves_length(map_item_chain_, update(index, new_item, the_items));
    //@ map_preserves_length(map_item_key_hash_, update(index, new_item, the_items));
    //@ map_update_update_map(map_item_key_addr_, index, new_item, the_items);
    //@ map_update_update_map(map_item_value_, index, new_item, the_items);
    //@ map_update_update_map(map_item_chain_, index, new_item, the_items);
    //@ map_update_update_map(map_item_key_hash_, index, new_item, the_items);
    //@ map_nth_nth_map(map_item_key_addr_, index, the_items);
    //@ map_nth_nth_map(map_item_value_, index, the_items);
    //@ map_nth_nth_map(map_item_key_hash_, index, the_items);
    //@ glue_items(raw_items, update(index, new_item, the_items), index);
  }
  //@ open mapp_core(key_size, real_capacity, ?kaddrs_lst, ?hashes_lst, ?values_lst, key_opts, map_values, map_addrs);
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
requires key_opt_list(?key_size, ?kaddrs, ?key_opts) &*&
         map_valuesaddrs(kaddrs, key_opts, ?values, ?map_values, ?map_addrs) &*&
         0 <= index &*& index < length(key_opts) &*&
         nth(index, key_opts) == some(?key) &*&
         ghostmap_get(map_values, key) != none &*&
         ghostmap_get(map_addrs, key) == some(?key_ptr) &*&
         key_ptr != NULL &*&
         true == opt_no_dups(key_opts) &*&
         true == ghostmap_distinct(map_values) &*&
         true == ghostmap_distinct(map_addrs);
ensures key_opt_list(key_size, update(index, NULL, kaddrs), update(index, none, key_opts)) &*&
        map_valuesaddrs(update(index, NULL, kaddrs), update(index, none, key_opts), values, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key)) &*&
        false == mem(some(key), update(index, none, key_opts)) &*&
        key_ptr != NULL &*&
        [0.25]chars(key_ptr, key_size, key);
{
  open key_opt_list(key_size, kaddrs, key_opts);
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
        close map_valuesaddrs(cons(NULL, kaddrst), cons(none, key_optst), values, map_values_rest, map_addrs_rest);
        close key_opt_list(key_size, cons(NULL, kaddrst), cons(none, key_optst));
      } else {
        switch(key_optsh) {
          case none:
            map_drop_key(index - 1);
            ghostmap_remove_preserves_distinct(map_values, key);
            ghostmap_remove_preserves_distinct(map_addrs, key);
            assert map_valuesaddrs(update(index - 1, NULL, kaddrst), update(index - 1, none, key_optst), valuest, ?new_map_values, ?new_map_addrs);
            close map_valuesaddrs(update(index, NULL, kaddrs), update(index, none, key_opts), values, new_map_values, new_map_addrs);
            close key_opt_list(key_size, update(index, NULL, kaddrs), update(index, none, key_opts));
          case some(kohv):
            ghostmap_remove_preserves_other(map_values, kohv, key);
            ghostmap_remove_preserves_other(map_addrs, kohv, key);
            map_drop_key(index - 1);
            ghostmap_remove_preserves_distinct(map_values, key);
            ghostmap_remove_preserves_distinct(map_addrs, key);
            close map_valuesaddrs(update(index, NULL, kaddrs), update(index, none, key_opts), values, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key));
            close key_opt_list(key_size, update(index, NULL, kaddrs), update(index, none, key_opts));
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

void map_remove(struct map* map, void* key_ptr)
/*@ requires mapp(map, ?key_size, ?capacity, ?map_values, ?map_addrs) &*&
             key_ptr != NULL &*&
             [?frac]chars(key_ptr, key_size, ?key) &*&
             frac != 0.0 &*&
             ghostmap_get(map_values, key) != none &*&
             ghostmap_get(map_addrs, key) == some(key_ptr); @*/
/*@ ensures mapp(map, key_size, capacity, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key)) &*&
           [frac + 0.25]chars(key_ptr, key_size, key); @*/
//@ terminates;
{
  //@ open mapp(map, key_size, capacity, map_values, map_addrs);
  hash_t key_hash = os_memory_hash(key_ptr, map->key_size);
  //@ open mapp_core(key_size, ?real_capacity, ?kaddrs_lst, ?hashes_lst, ?values_lst, ?key_opts, map_values, map_addrs);
  //@ map_values_has_implies_key_opts_has(key);
  //@ key_opts_has_implies_not_empty(key_opts, key);
  //@ close mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
  //@ size_t start = loop_fp(key_hash, real_capacity);
  //@ loop_lims(key_hash, real_capacity);
  //@ open buckets_keys_insync(real_capacity, ?old_chains_lst, ?buckets, key_opts);
  //@ buckets_keys_chns_same_len(buckets);
  //@ key_is_contained_in_the_bucket(buckets, real_capacity, key);
  //@ buckets_remove_add_one_chain(buckets, start, key);
  //@ loop_bijection(start, real_capacity);
  for (size_t i = 0; i < map->capacity; ++i)
    /*@ invariant mapp_raw(map, kaddrs_lst, hashes_lst, ?chains_lst, values_lst, key_size, real_capacity) &*&
                  mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs) &*&
                  is_pow2(real_capacity, N63) != none &*&
                  0 <= i &*& i <= real_capacity &*&
                  key_ptr != NULL &*&
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
    //@ open mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
    size_t index = loop(key_hash, i, map->capacity);
    struct map_item* item = &(map->items[index]);
    //@ assert map->items |-> ?raw_items;
    //@ assert map_itemsp(raw_items, real_capacity, ?the_items);
    //@ extract_item(raw_items, index);
    if (item->key_addr != NULL && item->key_hash == key_hash) {
      //@ nth_map(index, map_item_key_addr_, the_items);
      //@ nth_map(index, map_item_key_hash_, the_items);
      //@ close key_opt_list(key_size, nil, nil);
      //@ extract_key_at_index(nil, nil, index, kaddrs_lst, key_opts);
      //@ append_nil(reverse(take(index, kaddrs_lst)));
      //@ append_nil(reverse(take(index, key_opts)));
      //@ nth_map(index, map_item_key_addr_, the_items);
      if (os_memory_eq(item->key_addr, key_ptr, map->key_size)) {
        //@ recover_key_opt_list(kaddrs_lst, key_opts, index);
        //@ key_opt_list_find_key(key_opts, index, key);
        item->key_addr = NULL;
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
        //@ ghostmap_remove_preserves_distinct(map_values, key);
        //@ ghostmap_remove_preserves_distinct(map_addrs, key);
        //@ close mapp_core(key_size, real_capacity, update(index, NULL, kaddrs_lst), hashes_lst, values_lst, update(index, none, key_opts), ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key));
        //@ map_item new_item = map_item(NULL, map_item_value_(nth(index, the_items)), map_item_chain_(nth(index, the_items)), map_item_key_hash_(nth(index, the_items)));
        //@ take_update_unrelevant(index, index, new_item, the_items);
        //@ drop_update_unrelevant(index + 1, index, new_item, the_items);
        //@ map_preserves_length(map_item_key_addr_, update(index, new_item, the_items));
        //@ map_preserves_length(map_item_value_, update(index, new_item, the_items));
        //@ map_preserves_length(map_item_chain_, update(index, new_item, the_items));
        //@ map_preserves_length(map_item_key_hash_, update(index, new_item, the_items));
        //@ map_update_update_map(map_item_key_addr_, index, new_item, the_items);
        //@ map_update_update_map(map_item_value_, index, new_item, the_items);
        //@ map_update_update_map(map_item_chain_, index, new_item, the_items);
        //@ map_update_update_map(map_item_key_hash_, index, new_item, the_items);
        //@ map_nth_nth_map(map_item_key_addr_, index, the_items);
        //@ map_nth_nth_map(map_item_value_, index, the_items);
        //@ map_nth_nth_map(map_item_chain_, index, the_items);
        //@ map_nth_nth_map(map_item_key_hash_, index, the_items);
        //@ glue_items(raw_items, update(index, new_item, the_items), index);
        //@ close mapp(map, key_size, capacity, ghostmap_remove(map_values, key), ghostmap_remove(map_addrs, key));
        return;
      }
      //@ recover_key_opt_list(kaddrs_lst, key_opts, index);
    } else {
      //@ nth_map(index, map_item_key_addr_, the_items);
      //@ nth_map(index, map_item_key_hash_, the_items);
      //@ if (nth(index, map(map_item_key_addr_, the_items)) == NULL) no_bb_no_key(key_opts, kaddrs_lst, index); else no_hash_no_key(key_opts, hashes_lst, key, index);
    }
    //@ buckets_remove_key_same_len(buckets, key);
    //@ buckets_keys_chns_same_len(buckets_remove_key_fp(buckets, key));
    //@ buckets_get_chain_longer(buckets, start, i, key, real_capacity);
    //@ buckets_get_chns_nonneg(buckets_remove_key_fp(buckets, key));
    //@ add_part_chn_gt0(index, buckets_get_chain_fp(buckets, key, start) - i, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
    //@ nth_map(index, map_item_chain_, the_items);
    item->chain = item->chain - 1;
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
    //@ inc_modulo_loop(start + i, real_capacity);
    //@ assert loop_fp(loop_fp(start + i, real_capacity) + 1, real_capacity) == loop_fp(start + i + 1, real_capacity);
    //@ chains_lst = add_partial_chain_fp(loop_fp(start + i + 1, real_capacity), buckets_get_chain_fp(buckets, key, start) - i - 1, buckets_get_chns_fp(buckets_remove_key_fp(buckets, key)));
    //@ close mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
    //@ map_item new_item = map_item(map_item_key_addr_(nth(index, the_items)), map_item_value_(nth(index, the_items)), map_item_chain_(nth(index, the_items)) - 1, map_item_key_hash_(nth(index, the_items)));
    //@ take_update_unrelevant(index, index, new_item, the_items);
    //@ drop_update_unrelevant(index + 1, index, new_item, the_items);
    //@ map_preserves_length(map_item_key_addr_, update(index, new_item, the_items));
    //@ map_preserves_length(map_item_value_, update(index, new_item, the_items));
    //@ map_preserves_length(map_item_chain_, update(index, new_item, the_items));
    //@ map_preserves_length(map_item_key_hash_, update(index, new_item, the_items));
    //@ map_update_update_map(map_item_key_addr_, index, new_item, the_items);
    //@ map_update_update_map(map_item_value_, index, new_item, the_items);
    //@ map_update_update_map(map_item_chain_, index, new_item, the_items);
    //@ map_update_update_map(map_item_key_hash_, index, new_item, the_items);
    //@ map_nth_nth_map(map_item_key_addr_, index, the_items);
    //@ map_nth_nth_map(map_item_value_, index, the_items);
    //@ map_nth_nth_map(map_item_key_hash_, index, the_items);
    //@ glue_items(raw_items, update(index, new_item, the_items), index);
  }
  //@ open mapp_core(key_size, real_capacity, kaddrs_lst, hashes_lst, values_lst, key_opts, map_values, map_addrs);
  //@ by_loop_for_all(key_opts, (neq)(some(key)), start, real_capacity, nat_of_int(real_capacity));
  //@ no_key_found(key_opts, key);
  //@ assert false;
}
