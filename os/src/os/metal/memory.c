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
            (size_t) result % (size + CACHE_LINE_SIZE - (size % CACHE_LINE_SIZE)) == 0; @*/
//@ terminates;
{
	//@ mul_nonnegative(count, size);
	const size_t full_size = size * count;

	//@ produce_memory_assumptions();
	//@ open globals_invariant();
	//@ assert memory_used_len |-> ?memlen;
	//@ assert memory[memlen..MEMORY_SIZE] |-> ?mem;
	int8_t* target_addr = (int8_t*) memory + memory_used_len; // VeriFast requires the pointer cast

	// Aligning to the cache line size can make a huge positive performance difference sometimes, well worth the hassle
	// (e.g. one time TinyNF accidentally regressed by 40% throughput because of misalignment...)
	if (SIZE_MAX - CACHE_LINE_SIZE < size) {
	    os_debug("Object is too big to be alignable");
	    halt();
	}

	//@ div_rem_nonneg(size, CACHE_LINE_SIZE);
	const size_t align_div = size + CACHE_LINE_SIZE - (size % CACHE_LINE_SIZE);
	const size_t align_diff = (size_t) target_addr % align_div;

	//@ div_rem_nonneg((size_t) target_addr, align_div);
	const size_t align_padding = align_diff == 0 ? (size_t) 0 : align_div - align_diff; // VeriFast requires the cast on 0
	if (align_padding > MEMORY_SIZE - memory_used_len) {
		os_debug("Not enough memory left to align");
		halt();
	}

	// Leak the alignment memory, i.e., fragment the heap, since we don't support any notion of freeing
	//@ leak chars(target_addr, align_padding, _);
	//@ all_eq_drop(mem, align_padding, 0);

	//@ mod_compensate((size_t) target_addr, align_div);
	int8_t* aligned_addr = target_addr + align_padding;

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
