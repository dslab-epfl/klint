#include "os/memory.h"

#include "os/error.h"

//@ #include "proof/arith.gh"
//@ #include "proof/modulo.gh"

#define MEMORY_SIZE 0x1000000ull

extern void* memory; //[0x1000000]; // 256 MB should be enough?
static unsigned long long memory_used_len; // should be size_t but VeriFast doesn't support it


/*@
lemma void produce_memory_assumptions(void) // TODO lemma instead?
requires emp;
ensures memory |-> ?mem &*&
        memory_used_len |-> ?memlen &*&
        memlen <= MEMORY_SIZE &*&
        mem + MEMORY_SIZE <= (void*) UINTPTR_MAX &*&
        chars(mem + memlen, MEMORY_SIZE - memlen, ?cs) &*&
        true == all_eq(cs, 0);
{
	assume(false); // Provided by linker and by consume_memory_assumptions
}

lemma void consume_memory_assumptions(void)
requires memory |-> ?mem &*&
         memory_used_len |-> ?memlen &*&
         chars(mem + memlen, MEMORY_SIZE - memlen, _);
ensures emp;
{
	// These will be recovered on the next call to produce_memory_assumptions
	leak pointer(_, _);
	leak u_llong_integer(_, _);
	leak chars(mem + memlen, MEMORY_SIZE - memlen, _);
}
@*/

/*@
lemma void all_eq_take<t>(list<t> lst, int count, t value)
requires 0 <= count &*& count <= length(lst) &*&
         true == all_eq(lst, value);
ensures true == all_eq(take(count, lst), value);
{
	switch(lst) {
		case nil:
		case cons(hd, tl):
			assert hd == value;
			if (count != 0) {
				all_eq_take(tl, count - 1, value);
			}
	}
}
@*/

void* os_memory_alloc(size_t count, size_t size)
//@ requires count == 1 || count * size <= SIZE_MAX;
//@ ensures chars(result, count * size, ?cs) &*& true == all_eq(cs, 0) &*& result + count * size <= (char*) UINTPTR_MAX;
//@ terminates;
{
	//@ mul_nonnegative(count, size);
	const size_t full_size = size * count;

	// Weird but valid; return a zero address for debugging convenience
	if (full_size == 0) {
		return (void*) 0;
	}

	// Avoid overflows later
	if (full_size > MEMORY_SIZE) {
		os_fatal("Cannot satisfy such a big alloc request");
	}

	//@ produce_memory_assumptions();

	// Align as required by the contract
	const unsigned long long align_diff = (unsigned long long) (memory + memory_used_len) % full_size;
	//@ div_mod(align_diff, (unsigned long long) (memory + memory_used_len), full_size);
	//@ div_mod_gt_0(align_diff, (unsigned long long) (memory + memory_used_len), full_size);
	if (align_diff != 0) {
		if (full_size - align_diff > MEMORY_SIZE - memory_used_len) {
			os_fatal("Not enough space left to align");
		}

		// Leak the alignment memory, i.e., fragment the heap, since we don't support any notion of freeing
		//@ assert memory |-> ?mem;
		//@ assert memory_used_len |-> ?memlen;
		//@ chars_split(mem + memlen, full_size - align_diff);
		//@ leak chars(mem + memlen, full_size - align_diff, _);

		memory_used_len = memory_used_len + (full_size - align_diff);
		if (memory_used_len > MEMORY_SIZE) {
			os_fatal("Not enough space left after aligning");
		}
		//@ consume_memory_assumptions();
		//@ produce_memory_assumptions();
	}

	if (MEMORY_SIZE - memory_used_len < full_size) {
		os_fatal("Not enough space left to allocate");
	}

	int8_t* result = memory + memory_used_len;
	//@ assert memory |-> ?mem;
	//@ assert memory_used_len |-> ?memlen;
	//@ assert chars(mem + memlen, MEMORY_SIZE - memlen, ?cs);
	//@ chars_split(mem + memlen, full_size);
	//@ chars_split(result, full_size);
	//@ all_eq_take(cs, full_size, 0);
	memory_used_len = memory_used_len + full_size;
	return result;
	//@ consume_memory_assumptions();
}

void* os_memory_phys_to_virt(uintptr_t addr, size_t size)
//@ requires emp;
//@ ensures emp;
//@ terminates;
{
	// phys == virt, no protections
	(void) size;
	return (void*) addr;
}

uintptr_t os_memory_virt_to_phys(const void* addr)
//@ requires emp;
//@ ensures emp;
//@ terminates;
{
	// phys == virt
	return (uintptr_t) addr;
}
