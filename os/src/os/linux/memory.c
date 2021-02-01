// The only way to have pinned pages on Linux is to use huge pages: https://www.kernel.org/doc/Documentation/vm/hugetlbpage.txt
// Note that Linux's `mlock` system call is not sufficient to pin; it only guarantees the pages will not be swapped out, not that the physical address won't change.
// While Linux doesn't actually guarantee that huge pages are pinned, in practice its implementation pins them.

#include "os/memory.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include "os/fail.h"


// We only support 2MB hugepages
#define HUGEPAGE_SIZE_POWER (10 + 10 + 1)
#define HUGEPAGE_SIZE (1u << HUGEPAGE_SIZE_POWER)

// glibc defines it but musl doesn't
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif


size_t os_memory_pagesize(void)
{
	// sysconf is documented to return -1 on error; let's check all negative cases along the way, to make sure the conversion to unsigned is sound
	const long page_size_long = sysconf(_SC_PAGESIZE);
	if (page_size_long < 0) {
		os_fail("Page size is negative?!?");
	}
	if ((unsigned long) page_size_long > SIZE_MAX) {
		os_fail("Page size too big for size_t");
	}
	if (page_size_long == 0) {
		os_fail("Could not get page size");
	}
	return page_size_long;
}

void* os_memory_alloc(const size_t count, const size_t size)
{
	// OK because of the contract, this cannot overflow
	const size_t full_size = size * count;

	// OK if size is smaller, we'll just return too much memory
	if (full_size > HUGEPAGE_SIZE) {
return malloc(full_size); // TODO proper memory allocation with 1 GB hugepages...
//		os_fail("Full size too big");
	}

	// http://man7.org/linux/man-pages//man2/munmap.2.html
	void* page = mmap(
		// No specific address
		NULL,
		// Size of the mapping
		HUGEPAGE_SIZE,
		// R/W page
		PROT_READ | PROT_WRITE,
		// Hugepage, not backed by a file (and thus zero-initialized); note that without MAP_SHARED the call fails
		// MAP_POPULATE means the page table will be populated already (without the need for a page fault later),
		// which is required if the calling code tries to get the physical address of the page without accessing it first.
		MAP_HUGETLB | (HUGEPAGE_SIZE_POWER << MAP_HUGE_SHIFT) | MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE,
		// Required on MAP_ANONYMOUS
		-1,
		// Required on MAP_ANONYMOUS
		0
	);
	if (page == MAP_FAILED) {
		os_fail("Allocate mmap failed");
	}

	return page;
}

void* os_memory_phys_to_virt(const uintptr_t addr, const size_t size)
{
	if (addr != (uintptr_t) (off_t) addr) {
		os_fail("Cannot phys-to-virt an addr that does not roundtrip to off_t");
	}

	int mem_fd = open("/dev/mem", O_SYNC | O_RDWR);
	if (mem_fd == -1) {
		os_fail("Could not open /dev/mem");
	}

	void* mapped = mmap(
		// No specific address
		NULL,
		// Size of the mapping
		size,
		// R/W page
		PROT_READ | PROT_WRITE,
		// Send updates to the underlying "file"
		MAP_SHARED,
		// /dev/mem
		mem_fd,
		// Offset is the address (cast OK because we checked above)
		(off_t) addr
	);

	// nothing we can do if this fails, since we didn't write don't even bother checking
	close(mem_fd);

	if (mapped == MAP_FAILED) {
		os_fail("Phys-to-virt mmap failed");
	}

	return mapped;
}

// See https://www.kernel.org/doc/Documentation/vm/pagemap.txt
uintptr_t os_memory_virt_to_phys(const void* const addr)
{
	const size_t page_size = os_memory_pagesize();
	const uintptr_t page = (uintptr_t) addr / page_size;
	const uintptr_t map_offset = page * sizeof(uint64_t);
	if (map_offset != (uintptr_t) (off_t) map_offset) {
		os_fail("Cannot virt-to-phys with an offset that does not roundtrip to off_t");
	}

	const int map_fd = open("/proc/self/pagemap", O_RDONLY);
	if (map_fd < 0) {
		os_fail("Could not open the pagemap");
	}

	if (lseek(map_fd, (off_t) map_offset, SEEK_SET) == (off_t) -1) {
		os_fail("Could not seek the pagemap");
	}

	uint64_t metadata;
	const ssize_t read_result = read(map_fd, &metadata, sizeof(uint64_t));
	close(map_fd);
	if (read_result != sizeof(uint64_t)) {
		os_fail("Could not read the pagemap");
	}

	// We want the PFN, but it's only meaningful if the page is present; bit 63 indicates whether it is
	if ((metadata & 0x8000000000000000) == 0) {
		os_fail("Page not present");
	}
	// PFN = bits 0-54
	const uint64_t pfn = metadata & 0x7FFFFFFFFFFFFF;
	if (pfn == 0) {
		os_fail("Page not mapped");
	}

	const uintptr_t addr_offset = (uintptr_t) addr % page_size;
	return pfn * page_size + addr_offset;
}
