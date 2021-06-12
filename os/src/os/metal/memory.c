#include "os/memory.h"

#include "arch/halt.h"
#include "os/log.h"

//@ #include "proof/listexex.gh"
//@ #include "proof/modulo.gh"


 // 256 MB should be enough?
#define MEMORY_SIZE 0x1000000ull

static int8_t memory[MEMORY_SIZE]; // zero-initialized
static size_t memory_used_len;


/*@
// This globals invariant holds at the start, assuming the compiler and linker are correct
// TODO this '&memory >= 0' is only necessary when 'memory' is typed as an int8_t[], not an uint8_t[], is VeriFast incorrectly propagating signs?
predicate globals_invariant() =
	memory_used_len |-> ?memlen &*&
	&memory >= 0 &*&
        memlen <= MEMORY_SIZE &*&
        &memory + MEMORY_SIZE <= (void*) UINTPTR_MAX &*&
        memory[memlen..MEMORY_SIZE] |-> ?cs &*&
        true == all_eq(cs, 0);

lemma void produce_memory_assumptions(void)
requires emp;
ensures globals_invariant();
{
	assume(false);
}

lemma void consume_memory_assumptions(void)
requires globals_invariant();
ensures emp;
{
	assume(false);
}
@*/


void* os_memory_alloc(size_t count, size_t size)
//@ requires count * size <= SIZE_MAX;
/*@ ensures chars(result, count * size, ?cs) &*& true == all_eq(cs, 0) &*& result + count * size <= (char*) UINTPTR_MAX &*&
            (size_t) result % ((count * size) + CACHE_LINE_SIZE - ((count * size) % CACHE_LINE_SIZE)) == 0; @*/
//@ terminates;
{
	//@ mul_nonnegative(count, size);
	size_t mul_size = size * count;

	// Handle zero specially, since we use modulo full_size to align
	if (mul_size == 0) {
		// Return a zero address for debugging convenience
		//@ div_rem_nonneg(count * size, 64);
		return (void*) 0;
	}

	// Align to the cache line size (this can make a huge positive performance difference sometimes)
	//@ div_rem_nonneg(mul_size, CACHE_LINE_SIZE);
	const size_t cache_padding = (CACHE_LINE_SIZE - (mul_size % CACHE_LINE_SIZE));
	if (SIZE_MAX - cache_padding < mul_size) {
		os_debug("Not enough memory left to cache-align");
		halt();
	}
	const size_t full_size = mul_size + cache_padding;

	//@ produce_memory_assumptions();
	//@ open globals_invariant();
	//@ assert memory_used_len |-> ?memlen;
	//@ assert memory[memlen..MEMORY_SIZE] |-> ?mem;
	const int8_t* target_addr = (int8_t*) memory + memory_used_len; // VeriFast requires the pointer cast

	const size_t align_diff = (size_t) target_addr % full_size;
	//@ div_rem_nonneg((size_t)target_addr, full_size);
	const size_t align_padding = align_diff == 0 ? (size_t) 0 : full_size - align_diff; // VeriFast requires the cast on 0

	if (align_padding > MEMORY_SIZE - memory_used_len) {
		os_debug("Not enough memory left to align");
		halt();
	}

	// Leak the alignment memory, i.e., fragment the heap, since we don't support any notion of freeing
	//@ leak chars(target_addr, align_padding, _);
	//@ all_eq_drop(mem, align_padding, 0);

	//@ mod_compensate((size_t) target_addr, full_size);
	const int8_t* aligned_addr = target_addr + align_padding;

	memory_used_len = memory_used_len + align_padding;
	if (full_size > MEMORY_SIZE - memory_used_len) {
		os_debug("Not enough memory left to allocate");
		halt();
	}

	//@ chars_split((int8_t*) memory + memlen + align_padding, full_size);
	//@ chars_split(aligned_addr, full_size);
	//@ all_eq_take(drop(align_padding, mem), full_size, 0);
	//@ all_eq_drop(drop(align_padding, mem), full_size, 0);
	memory_used_len = memory_used_len + full_size;

	//@ assert chars(aligned_addr, full_size, ?result_chars);
	//@ chars_split(aligned_addr, mul_size);
	//@ leak chars(aligned_addr + mul_size, cache_padding, _);
	//@ all_eq_take(result_chars, mul_size, 0);
	return aligned_addr;
	//@ close globals_invariant();
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
