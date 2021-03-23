#include "os/memory.h"

#include "os/error.h"

//@ #include "proof/arith.gh"
//@ #include "proof/listexex.gh"
//@ #include "proof/modulo.gh"

 // 256 MB should be enough?
#define MEMORY_SIZE 0x1000000ull

static uint8_t memory[MEMORY_SIZE]; // zero-initialized
static unsigned long long memory_used_len; // should be size_t but VeriFast doesn't support it


/*@
// This globals invariant holds at the start, assuming the compiler and linker are correct
predicate globals_invariant() =
	memory_used_len |-> ?memlen &*&
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
//@ requires count == 1 || count * size <= SIZE_MAX;
/*@ ensures uchars(result, count * size, ?cs) &*& true == all_eq(cs, 0) &*& result + count * size <= (char*) UINTPTR_MAX &*& 
            count*size == 0 ? true : (size_t) result % (count * size) == 0; @*/
//@ terminates;
{
	//@ mul_nonnegative(count, size);
	const size_t full_size = size * count;

	// Handle zero specially, since we use modulo full_size to align
	if (full_size == 0) {
		// Return a zero address for debugging convenience
		return (void*) 0;
	}

	//@ produce_memory_assumptions();
	//@ open globals_invariant();
	//@ assert memory_used_len |-> ?memlen;
	//@ assert memory[memlen..MEMORY_SIZE] |-> ?mem;

	uint8_t* target_addr = (uint8_t*) memory + memory_used_len; // VeriFast requires the pointer cast
	const size_t align_diff = (size_t) target_addr % full_size;
	//@ div_mod_gt_0(align_diff, (size_t) target_addr, full_size);
	const size_t align_padding = align_diff == 0 ? (size_t) 0 : full_size - align_diff; // VeriFast requires the cast on 0

	if (align_padding > MEMORY_SIZE - memory_used_len) {
		os_fatal("Not enough memory left to align");
	}

	// Leak the alignment memory, i.e., fragment the heap, since we don't support any notion of freeing
	//@ uchars_split(target_addr, align_padding);
	//@ leak uchars(target_addr, align_padding, _);
	//@ all_eq_drop(mem, align_padding, 0);

	//@ mod_compensate((size_t) target_addr, full_size);
	target_addr = target_addr + align_padding;
	//@ assert (size_t) target_addr % full_size == 0;
	
	memory_used_len = memory_used_len + align_padding;
	if (full_size > MEMORY_SIZE - memory_used_len) {
		os_fatal("Not enough memory left to allocate");
	}

	//@ uchars_split((uint8_t*) memory + memlen + align_padding, full_size);
	//@ uchars_split(target_addr, full_size);
	//@ all_eq_take(drop(align_padding, mem), full_size, 0);
	//@ all_eq_drop(drop(align_padding, mem), full_size, 0);
	memory_used_len = memory_used_len + full_size;
	
	return target_addr;
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
