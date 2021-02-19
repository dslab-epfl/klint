#include "structs/pool.h"

#include "os/memory.h"

//@ #include "proof/listexex.gh"

// IMPLEMENTATION NOTES:
	// Note that 'ghostmap_get(items, index) != none' is not necessary in this implementation for refresh and return.
	// But it should help in other implementations, e.g. using separate linked lists for free/occupied.
	// So we leave it there, because the usefulness of removing the requirement is limited.
// PROOF NOTES:
	// Weird things Redux cannot figure out without these hints
// TODO: Write more
// TODO: Try the 'note' workaround instead of the hacky lemmas (also in ghost_map.gh!)


// TODO: Redux triggers some inconsistencies, see console output; but Z3 is fine; probably need to minimize an example and report it...

struct os_pool {
	time_t* timestamps;
	size_t size;
	time_t expiration_time;
};

/*@
fixpoint bool idx_in_bounds<t>(size_t i, list<t> xs) { return 0 <= i && i < length(xs); }
fixpoint bool nth_eq<t>(size_t i, list<t> xs, t x) { return nth(i, xs) == x; }

predicate poolp_raw(struct os_pool* pool; size_t size, time_t expiration_time, list<time_t> timestamps) =
	struct_os_pool_padding(pool) &*&
	pool->size |-> size &*&
	pool->expiration_time |-> expiration_time &*&
	pool->timestamps |-> ?raw_timestamps &*&
	PRED_times(raw_timestamps, size, timestamps);

predicate poolp_truths(list<time_t> timestamps, list<pair<size_t, time_t> > items) =
	true == ghostmap_distinct(items) &*&
	forall_(size_t k; (idx_in_bounds(k, timestamps) && !nth_eq(k, timestamps, TIME_INVALID)) == ghostmap_has(items, k)) &*&
	forall_(size_t k; !ghostmap_has(items, k) || ghostmap_get(items, k) == some(nth(k, timestamps)));

predicate poolp(struct os_pool* pool, size_t size, time_t expiration_time, list<pair<size_t, time_t> > items) =
	poolp_raw(pool, size, expiration_time, ?timestamps) &*&
	poolp_truths(timestamps, items);
@*/

struct os_pool* os_pool_alloc(size_t size, time_t expiration_time)
/*@ requires emp; @*/
/*@ ensures poolp(result, size, expiration_time, nil); @*/
{
	struct os_pool* pool = (struct os_pool*) os_memory_alloc(1, sizeof(struct os_pool));
	//@ close_struct_zero(pool);
	pool->timestamps = (time_t*) os_memory_alloc(size, sizeof(time_t));
	pool->size = size;
	pool->expiration_time = expiration_time;

	for (size_t n = size; n > 0; n--)
	/*@ invariant pool->timestamps |-> ?raw_timestamps &*& 
	              chars((char*) raw_timestamps, n * sizeof(time_t), _) &*&
	              PRED_times(raw_timestamps + n, size - n, ?timestamps) &*&
	              true == all_eq(timestamps, TIME_INVALID); @*/
	{
		//@ chars_split((char*) raw_timestamps, (n - 1) * sizeof(time_t));
		//@ chars_to_time(raw_timestamps + n - 1);
		pool->timestamps[n - 1] = TIME_INVALID;
	}

	//@ assert pool->timestamps |-> ?raw_timestamps;
	//@ assert PRED_times(raw_timestamps, size, ?timestamps);
	//@ forall_eq_nth(timestamps, TIME_INVALID);
	//@ close poolp_truths(timestamps, nil);
	//@ close poolp(pool, size, expiration_time, nil);
	return pool;
}

/*@
lemma void pool_not_full(list<pair<size_t, time_t> > items, size_t index)
requires poolp_truths(?timestamps, items) &*&
         true == nth_eq(index, timestamps, TIME_INVALID);
ensures poolp_truths(timestamps, items) &*&
        length(items) != length(timestamps);
{
	assume(false);
}
lemma void pool_not_young(list<pair<size_t, time_t> > items, size_t index, time_t time, time_t exp_time)
requires poolp_truths(?timestamps, items) &*&
         time >= exp_time &*&
         time - exp_time > nth(index, timestamps);
ensures poolp_truths(timestamps, items) &*&
        false == ghostmap_forall(items, (pool_young)(time, exp_time));
{
	assume(false);
}

lemma void truths_update_borrow(list<pair<size_t, time_t> > items, size_t index, time_t time)
requires poolp_truths(?timestamps, items) &*&
         time != TIME_INVALID;
ensures poolp_truths(update(index, time, timestamps), ghostmap_set(items, index, time));
{
	assume(false);
}

lemma void pool_items_implication_tail(list<pair<size_t, time_t> > items, list<time_t> timestamps, time_t time, time_t exp_time)
requires items == cons(?h, ?t) &*&
         true == ghostmap_distinct(items) &*&
         forall_(size_t k; !ghostmap_has(items, k) || (ghostmap_get(items, k) == some(nth(k, timestamps))));
ensures forall_(size_t k; !ghostmap_has(t, k) || (ghostmap_get(t, k) == some(nth(k, timestamps))));
{
	assert h == pair(?hk, ?hv);
	assert !ghostmap_has(t, hk);
}

lemma void pool_items_young_forall_to_ghostmap(list<pair<size_t, time_t> > items, list<time_t> timestamps, time_t time, time_t exp_time)
requires true == ghostmap_distinct(items) &*&
         forall_(size_t k; !ghostmap_has(items, k) || (ghostmap_get(items, k) == some(nth(k, timestamps)))) &*&
         forall_(size_t k; !ghostmap_has(items, k) || (time < exp_time || time - exp_time <= nth(k, timestamps)));
ensures true == ghostmap_forall(items, (pool_young)(time, exp_time));
{
	switch (items) {
		case nil:
		case cons(h, t):
			assert h == pair(?hk, ?hv);
			pool_items_implication_tail(items, timestamps, time, exp_time);
			pool_items_young_forall_to_ghostmap(t, timestamps, time, exp_time);
			assert ghostmap_get(items, hk) == some(hv);
	}
}
@*/

bool os_pool_borrow(struct os_pool* pool, time_t time, size_t* out_index, bool* out_used)
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
             time != TIME_INVALID &*&
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
{
	//@ open poolp(pool, size, exp_time, items);
	//@ open poolp_truths(?timestamps, items);
	//@ close poolp_truths(timestamps, items);
	for (size_t n = 0; n < pool->size; n++)
	/*@ invariant poolp_raw(pool, size, exp_time, timestamps) &*&
	              poolp_truths(timestamps, items) &*&
	              *out_index |-> _ &*&
	              *out_used |-> _ &*&
	              forall_(size_t k; !(0 <= k && k < n) || !nth_eq(k, timestamps, TIME_INVALID)) &*&
	              forall_(size_t k; !(0 <= k && k < n) || (time < exp_time || time - exp_time <= nth(k, timestamps))); @*/
	{
		//@ close poolp_raw(pool, size, exp_time, timestamps);
		if (pool->timestamps[n] == TIME_INVALID) {
			//@ pool_not_full(items, n);
			pool->timestamps[n] = time;
			*out_index = n;
			*out_used = false;
			//@ truths_update_borrow(items, n, time);
			//@ close poolp(pool, size, exp_time, ghostmap_set(items, n, time));
			return true;
		}
		if (time >= pool->expiration_time && time - pool->expiration_time > pool->timestamps[n]) {
			//@ pool_not_young(items, n, time, exp_time);
			pool->timestamps[n] = time;
			*out_index = n;
			*out_used = true;
			//@ truths_update_borrow(items, n, time);
			//@ close poolp(pool, size, exp_time, ghostmap_set(items, n, time));
			return true;
		}
	}
	//@ open poolp_truths(timestamps, items);
	//@ ghostmap_array_size(items, size);
	//@ pool_items_young_forall_to_ghostmap(items, timestamps, time, exp_time);
	//@ close poolp_truths(timestamps, items);
	//@ close poolp(pool, size, exp_time, items);
	return false;
}

/*@
lemma void refresh_forall_close_loophole1(size_t index, time_t time, list<time_t> timestamps, list<pair<size_t, time_t> > items)
requires forall_(size_t k; ((idx_in_bounds(k, timestamps) && !nth_eq(k, update(index, time, timestamps), TIME_INVALID)) == ghostmap_has(ghostmap_set(items, index, time), k)) || k == index);
ensures forall_(size_t k; ((idx_in_bounds(k, update(index, time, timestamps)) && !nth_eq(k, update(index, time, timestamps), TIME_INVALID)) == ghostmap_has(ghostmap_set(items, index, time), k)) || k == index);
{
}	
lemma void refresh_forall_close_loophole2(size_t index, time_t time, list<time_t> timestamps, list<pair<size_t, time_t> > items)
requires forall_(size_t k; ((idx_in_bounds(k, update(index, time, timestamps)) && !nth_eq(k, update(index, time, timestamps), TIME_INVALID)) == ghostmap_has(ghostmap_set(items, index, time), k)) || k == index) &*&
        (idx_in_bounds(index, update(index, time, timestamps)) && !nth_eq(index, update(index, time, timestamps), TIME_INVALID)) == ghostmap_has(ghostmap_set(items, index, time), index);
ensures forall_(size_t k; (idx_in_bounds(k, update(index, time, timestamps)) && !nth_eq(k, update(index, time, timestamps), TIME_INVALID)) == ghostmap_has(ghostmap_set(items, index, time), k));	
{
}

lemma void truths_update_refresh(list<pair<size_t, time_t> > items, size_t index, time_t time)
requires poolp_truths(?timestamps, items) &*&
         true == idx_in_bounds(index, timestamps) &*&
         time != TIME_INVALID;
ensures poolp_truths(update(index, time, timestamps), ghostmap_set(items, index, time));
{
	open poolp_truths(timestamps, items);
	forall_nth_unchanged(index, time, timestamps);
	refresh_forall_close_loophole1(index, time, timestamps, items);
	refresh_forall_close_loophole2(index, time, timestamps, items);
	close poolp_truths(update(index, time, timestamps), ghostmap_set(items, index, time));
}
@*/

void os_pool_refresh(struct os_pool* pool, time_t time, size_t index)
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
             time != TIME_INVALID &*&
             index < size &*&
             ghostmap_get(items, index) != none; @*/
/*@ ensures poolp(pool, size, exp_time, ghostmap_set(items, index, time)); @*/
{
	//@ open poolp(pool, size, exp_time, items);
	pool->timestamps[index] = time;
	//@ truths_update_refresh(items, index, time);
	//@ close poolp(pool, size, exp_time, ghostmap_set(items, index, time));
}

/*@
lemma void index_too_large(size_t index, list<pair<size_t, time_t> > items)
requires poolp_truths(?timestamps, items) &*&
         index >= length(timestamps);
ensures poolp_truths(timestamps, items) &*&
        ghostmap_get(items, index) == none;
{
	open poolp_truths(timestamps, items);
	switch (ghostmap_get(items, index)) {
		case none:
		case some(ts):
			assert !idx_in_bounds(index, timestamps);
			assert false;
	}
	close poolp_truths(timestamps, items);
}
@*/

bool os_pool_used(struct os_pool* pool, size_t index, time_t* out_time)
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
             *out_time |-> _; @*/
/*@ ensures poolp(pool, size, exp_time, items) &*&
            switch (ghostmap_get(items, index)) {
              case none: return result == false &*& *out_time |-> _;
              case some(t): return result == true &*& *out_time |-> t;
            }; @*/
{
	//@ open poolp(pool, size, exp_time, items);
	if (index >= pool->size) {
		//@ index_too_large(index, items);
		//@ close poolp(pool, size, exp_time, items);
		return false;
	}
	//@ close poolp_raw(pool, size, exp_time, ?timestamps);
	//@ open poolp_truths(timestamps, items);
	*out_time = pool->timestamps[index];
	return *out_time != TIME_INVALID;
	//@ close poolp_truths(timestamps, items);
	//@ close poolp(pool, size, exp_time, items);
}

/*@
lemma void return_forall_close_loophole1(size_t index, list<time_t> timestamps, list<pair<size_t, time_t> > items)
requires forall_(size_t k; ((idx_in_bounds(k, timestamps) && !nth_eq(k, update(index, TIME_INVALID, timestamps), TIME_INVALID)) == ghostmap_has(ghostmap_remove(items, index), k)) || k == index);
ensures forall_(size_t k; ((idx_in_bounds(k, update(index, TIME_INVALID, timestamps)) && !nth_eq(k, update(index, TIME_INVALID, timestamps), TIME_INVALID)) == ghostmap_has(ghostmap_remove(items, index), k)) || k == index);
{
}
lemma void return_forall_close_loophole2(size_t index, list<time_t> timestamps, list<pair<size_t, time_t> > items)
requires forall_(size_t k; ((idx_in_bounds(k, timestamps) && !nth_eq(k, timestamps, TIME_INVALID)) == ghostmap_has(items, k)) || k == index) &*&
         (idx_in_bounds(index, timestamps) && !nth_eq(index, timestamps, TIME_INVALID)) == ghostmap_has(items, index);
ensures forall_(size_t k; (idx_in_bounds(k, timestamps) && !nth_eq(k, timestamps, TIME_INVALID)) == ghostmap_has(items, k));
{
}

lemma void truths_update_return(list<pair<size_t, time_t> > items, size_t index)
requires poolp_truths(?timestamps, items) &*&
         true == idx_in_bounds(index, timestamps);
ensures poolp_truths(update(index, TIME_INVALID, timestamps), ghostmap_remove(items, index));
{
	open poolp_truths(timestamps, items);
	forall_nth_unchanged(index, TIME_INVALID, timestamps);
	ghostmap_get_none_after_remove(items, index);
	return_forall_close_loophole1(index, timestamps, items);
	return_forall_close_loophole2(index, update(index, TIME_INVALID, timestamps), ghostmap_remove(items, index));
	close poolp_truths(update(index, TIME_INVALID, timestamps), ghostmap_remove(items, index));
}
@*/

void os_pool_return(struct os_pool* pool, size_t index)
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
             index < size &*&
             ghostmap_get(items, index) != none; @*/
/*@ ensures poolp(pool, size, exp_time, ghostmap_remove(items, index)); @*/
{
	//@ open poolp(pool, size, exp_time, items);
	pool->timestamps[index] = TIME_INVALID;
	//@ truths_update_return(items, index);
	//@ close poolp(pool, size, exp_time, ghostmap_remove(items, index));
}