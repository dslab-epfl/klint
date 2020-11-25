# Standard/External libraries
import angr
import claripy

# Us
from ... import bitsizes
from ... import cast
from ... import utils
from ...exceptions import SymbexException

# void* os_memory_alloc(size_t count, size_t size);
# requires count == 1 || count * size <= SIZE_MAX;
# ensures chars(result, count * size, ?cs) &*& true == all_eq(cs, 0) &*& result + count * size <= (char*) UINTPTR_MAX;
class OsMemoryAlloc(angr.SimProcedure):
    def run(self, count, size):
        # Casts
        count = cast.size_t(count)
        size = cast.size_t(size)

        # Symbolism assumptions
        if size.symbolic:
            raise SymbexException("size cannot be symbolic")

        # Preconditions
        if utils.can_be_false(self.state.solver, (count == 1) | (count * size <= (2 ** bitsizes.size_t - 1))):
            raise SymbexException("Precondition does not hold: count == 1 || count * size <= SIZE_MAX")

        # Postconditions
        result = self.state.memory.allocate(count, size, name="allocated", default=claripy.BVV(0, self.state.solver.eval_one(size, cast_to=int) * 8))
        print("!!! os_memory_alloc", count, size, "->", result)
        return result

# No contract, not exposed publicly, only for symbex harnesses
class OsMemoryHavoc(angr.SimProcedure):
    def run(self, ptr):
        ptr = cast.ptr(ptr)
        print("!!! os_memory_havoc", ptr)
        self.state.memory.havoc(ptr)