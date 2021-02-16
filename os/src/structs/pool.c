#include "structs/pool.h"

#include "os/memory.h"

//@ #include "proof/listexex.gh"


struct os_pool {
	time_t* timestamps;
	size_t size;
	time_t expiration_time;
};
/*@
fixpoint bool key_in_range(list<time_t> timestamps, size_t k, time_t v) { return k < length(timestamps); }
fixpoint bool value_is_valid(size_t k, time_t v) { return v != TIME_INVALID; }
fixpoint bool key_is_nth(list<time_t> timestamps, size_t k, time_t v) { return nth(k, timestamps) == v; }

predicate poolp_items(size_t start, list<time_t> timestamps, list<pair<size_t, time_t> > items) =
	start == length(timestamps) ? items == nil
	                            : (poolp_items(start + 1, timestamps, ?items_rest) &*&
		                       nth(start, timestamps) == TIME_INVALID ? items == items_rest
		                                                              : (items_rest == ghostmap_remove(items, start) &*&
		                                                                 length(items_rest) == length(items) - 1 &*&
		                                                                 ghostmap_get(items, start) == some(nth(start, timestamps))));

predicate poolp(struct os_pool* pool, size_t size, time_t expiration_time, list<pair<size_t, time_t> > used_items) =
	struct_os_pool_padding(pool) &*&
	pool->size |-> size &*&
	pool->expiration_time |-> expiration_time &*&
	pool->timestamps |-> ?raw_timestamps &*&
	PRED_times(raw_timestamps, size, ?timestamps) &*&
	size == length(timestamps) &*&
	poolp_items(0, timestamps, used_items);
@*/

/*@
// Note: We repeat 3x the same lemma with a different predicate; would be nice to factor this out...

lemma void keys_in_range(size_t start)
requires poolp_items(start, ?timestamps, ?items) &*&
         start <= length(timestamps);
ensures poolp_items(start, timestamps, items) &*&
        true == ghostmap_forall(items, (key_in_range)(timestamps));
{
	open poolp_items(start, timestamps, items);
	if (start != length(timestamps)) {
		keys_in_range(start + 1);
		if (nth(start, timestamps) != TIME_INVALID) {
			ghostmap_extra_preserves_forall(items, (key_in_range)(timestamps), start, nth(start, timestamps));
		}
	}
	close poolp_items(start, timestamps, items);
}

lemma void values_are_valid(size_t start)
requires poolp_items(start, ?timestamps, ?items);
ensures poolp_items(start, timestamps, items) &*&
        true == ghostmap_forall(items, value_is_valid);
{
	open poolp_items(start, timestamps, items);
	if (start != length(timestamps)) {
		values_are_valid(start + 1);
		if (nth(start, timestamps) != TIME_INVALID) {
			ghostmap_extra_preserves_forall(items, value_is_valid, start, nth(start, timestamps));
		}
	}
	close poolp_items(start, timestamps, items);
}

lemma void keys_are_nth(size_t start)
requires poolp_items(start, ?timestamps, ?items);
ensures poolp_items(start, timestamps, items) &*&
        true == ghostmap_forall(items, (key_is_nth)(timestamps));
{
	open poolp_items(start, timestamps, items);
	if (start != length(timestamps)) {
		keys_are_nth(start + 1);
		if (nth(start, timestamps) != TIME_INVALID) {
			ghostmap_extra_preserves_forall(items, (key_is_nth)(timestamps), start, nth(start, timestamps));
		}
	}
	close poolp_items(start, timestamps, items);
}

lemma void valid_index_in(size_t start, size_t index)
requires poolp_items(start, ?timestamps, ?items) &*&
         start <= index &*& index < length(timestamps) &*&
         nth(index, timestamps) != TIME_INVALID;
ensures poolp_items(start, timestamps, items) &*&
        ghostmap_get(items, index) == some(nth(index, timestamps));
{
	open poolp_items(start, timestamps, items);
	switch (ghostmap_get(items, index)) {
		case none:
			if (start != length(timestamps)) {
				valid_index_in(start + 1, index);
			}
		case some(ts):
			close poolp_items(start, timestamps, items);
			keys_are_nth(start);
			open poolp_items(start, timestamps, items);
			ghostmap_forall_implies_pred(items, (key_is_nth)(timestamps), index, ts);
		
	}
	close poolp_items(start, timestamps, items);
}

lemma void invalid_index_not_in(size_t start, size_t index)
requires poolp_items(start, ?timestamps, ?items) &*&
         nth(index, timestamps) == TIME_INVALID;
ensures poolp_items(start, timestamps, items) &*&
        ghostmap_get(items, index) == none;
{
	open poolp_items(start, timestamps, items);
	switch (ghostmap_get(items, index)) {
		case none:
			if (start != length(timestamps)) {
				invalid_index_not_in(start + 1, index);
			}
		case some(ts):
			close poolp_items(start, timestamps, items);
			values_are_valid(start);
			keys_are_nth(start);
			open poolp_items(start, timestamps, items);
			ghostmap_forall_implies_pred(items, value_is_valid, index, ts);
			ghostmap_forall_implies_pred(items, (key_is_nth)(timestamps), index, ts);
			assert false;
	}
	close poolp_items(start, timestamps, items);
}
@*/

/*@
lemma void empty_items(list<time_t> timestamps)
requires true == all_eq(timestamps, TIME_INVALID);
ensures poolp_items(0, timestamps, nil);
{
	close poolp_items(length(timestamps), timestamps, nil);
	for (size_t n = length(timestamps); n > 0; n--)
	invariant 0 <= n &*& n <= length(timestamps) &*&
	          poolp_items(n, timestamps, nil);
	decreases n;
	{
		all_eq_nth(timestamps, TIME_INVALID, n - 1);
		close poolp_items(n - 1, timestamps, nil);
	}
}
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
	//@ empty_items(timestamps);
	//@ close poolp(pool, size, expiration_time, nil);
	return pool;
}

bool os_pool_borrow(struct os_pool* pool, time_t time, size_t* out_index, bool* out_used)
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
{
	//@ assume(false);
}

void os_pool_refresh(struct os_pool* pool, time_t time, size_t index)
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
             index < size &*&
             ghostmap_get(items, index) != none; @*/
/*@ ensures poolp(pool, size, exp_time, ghostmap_set(items, index, time)); @*/
{
	//@ assume(false);
}

/*@
lemma void index_too_large(size_t index)
requires poolp_items(?start, ?timestamps, ?items) &*&
         start <= length(timestamps) &*&
         index >= length(timestamps);
ensures poolp_items(start, timestamps, items) &*&
        ghostmap_get(items, index) == none;
{
	open poolp_items(start, timestamps, items);
	switch (ghostmap_get(items, index)) {
		case none:
		case some(ts):
			close poolp_items(start, timestamps, items);
			keys_in_range(start);
			open poolp_items(start, timestamps, items);
			ghostmap_forall_implies_pred(items, (key_in_range)(timestamps), index, ts);
			assert false;
	}
	close poolp_items(start, timestamps, items);
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
		//@ index_too_large(index);
		//@ close poolp(pool, size, exp_time, items);
		return false;
	}
	/*@
	if (pool->timestamps[index] == TIME_INVALID) {
		invalid_index_not_in(0, index);
	} else {
		valid_index_in(0, index);
	}
	@*/
	*out_time = pool->timestamps[index];
	return *out_time != TIME_INVALID;
	//@ close poolp(pool, size, exp_time, items);
}

/*@
lemma void items_update_remove(size_t start, size_t index)
requires poolp_items(start, ?timestamps, ?items) &*&
         nth(index, timestamps) != TIME_INVALID &*&
         start <= index &*& index < length(timestamps);
ensures poolp_items(start, update(index, TIME_INVALID, timestamps), ghostmap_remove(items, index));
{
	open poolp_items(start, timestamps, items);
	assume(false); // TODO...
	if (start == index) {
	} else {
		//items_update_remove(start + 1, index);
	}
	close poolp_items(start, update(index, TIME_INVALID, timestamps), ghostmap_remove(items, index));
}
@*/

void os_pool_return(struct os_pool* pool, size_t index)
/*@ requires poolp(pool, ?size, ?exp_time, ?items) &*&
             index < size &*&
             ghostmap_get(items, index) != none; @*/
/*@ ensures poolp(pool, size, exp_time, ghostmap_remove(items, index)); @*/
{
	//@ open poolp(pool, size, exp_time, items);
	//@ assert poolp_items(0, ?timestamps, items);
	/*@
	if (nth(index, timestamps) == TIME_INVALID) {
		invalid_index_not_in(0, index);
		assert false;
	}
	@*/
	pool->timestamps[index] = TIME_INVALID;
	//@ items_update_remove(0, index);
	//@ close poolp(pool, size, exp_time, ghostmap_remove(items, index));
}