import angr
import claripy
import executors.binary.bitsizes as bitsizes
import executors.binary.cast as cast
import executors.binary.clock as clock
import executors.binary.utils as utils
from collections import namedtuple
from .pool import Pool
from executors.binary.exceptions import SymbexException

# predicate poolp(struct os_pool* pool, size_t size, list<pair<size_t, time_t> > items);
Cht = namedtuple("chtp", ["cht_height", "backend_capacity"])

MAX_CHT_HEIGHT = 40000

class ChtAlloc(angr.SimProcedure):
    def run(self, cht_height, backend_capacity):
        # Casts
        cht_height = cast.uint32_t(cht_height)
        backend_capacity = cast.uint32_t(backend_capacity)
        print(f"!!! cht_alloc [cht_height: {cht_height}, backend_capcity: {backend_capacity}]")

        # Preconditions
        precond = claripy.And(
            0 < cht_height, cht_height < MAX_CHT_HEIGHT,
            0 < backend_capacity, backend_capacity < cht_height, 
            cht_height * backend_capacity < (2 ** bitsizes.uint32_t - 1)
        )
        if utils.can_be_false(self.state.solver, precond):
            raise SymbexException("Precondition does not hold.")

        # Postconditions
        result = self.state.memory.allocate_opaque("cht")
        self.state.metadata.set(result, Cht(cht_height, backend_capacity))
        return result


class ChtFindPreferredAvailableBackend(angr.SimProcedure):
    def run(self, cht, hash, active_backends, chosen_backend):
        # Casts
        cht = cast.ptr(cht)
        hash = cast.uint64_t(hash)
        active_backends = cast.ptr(active_backends)
        chosen_backend = cast.ptr(chosen_backend)
        print(  f"!!! cht_find_preferred_available_backend [hash: {hash}, " +
                f"active_backends: {active_backends}, chosen_backend: {chosen_backend}]" )

        # Symbolism assumptions
        if chosen_backend.symbolic:
            raise SymbexException("chosen_backend cannot be symbolic")

        # Preconditions
        cht = self.state.metadata.get(Cht, cht)
        active_backends = self.state.metadata.get(Pool, active_backends)
        self.state.memory.load(chosen_backend, bitsizes.size_t // 8)
        if utils.can_be_false(self.state.solver, cht.backend_capacity.zero_extend(32) <= active_backends.size):
            raise SymbexException("Precondition does not hold.")

        # Postconditions
        backend = claripy.BVS("backend", bitsizes.uint32_t)

        def case_true(state):
            print("!!! cht_find_preferred_available_backend: did not find available backend")
            return claripy.BVV(0, bitsizes.bool)
        def case_false(state):
            print("!!! cht_find_preferred_available_backend: found available backend")
            state.memory.store(chosen_backend, backend, endness=self.state.arch.memory_endness)
            state.add_constraints(0 <= backend, backend < cht.backend_capacity)
            utils.add_constraints_and_check_sat(state, state.maps.get(active_backends.items, backend)[1])
            return claripy.BVV(1, bitsizes.bool)

        guard = self.state.maps.forall(active_backends.items, lambda k, v: claripy.And(k < 0, k >= cht.backend_capacity))
        return utils.fork_guarded(self, guard, case_true, case_false)

class AngrBreakpoint(angr.SimProcedure):
    def run(self):
        print("!!! angr_breakpoint")