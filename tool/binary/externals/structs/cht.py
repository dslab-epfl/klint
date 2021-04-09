import angr
import claripy
from collections import namedtuple

from .index_pool import Pool
import binary.utils as utils

# predicate poolp(struct os_pool* pool, size_t size, list<pair<size_t, time_t> > items);
Cht = namedtuple("chtp", ["cht_height", "backend_capacity"])

MAX_CHT_HEIGHT = 40000

class ChtAlloc(angr.SimProcedure):
    def run(self, cht_height, backend_capacity):
        # Casts
        cht_height = self.state.casts.size_t(cht_height)
        backend_capacity = self.state.casts.size_t(backend_capacity)

        # Preconditions
        self.state.solver.add(
            0 < cht_height, cht_height < MAX_CHT_HEIGHT,
            0 < backend_capacity, backend_capacity < cht_height, 
            cht_height * backend_capacity < (2 ** self.state.sizes.uint32_t - 1)
        )

        # Postconditions
        result = claripy.BVS("cht", self.state.sizes.ptr)
        self.state.metadata.append(result, Cht(cht_height, backend_capacity))
        print(f"!!! cht_alloc [cht_height: {cht_height}, backend_capcity: {backend_capacity}] -> {result}")
        return result


class ChtFindPreferredAvailableBackend(angr.SimProcedure):
    def run(self, cht, obj, obj_size, active_backends, chosen_backend, time):
        # Casts
        cht = self.state.casts.ptr(cht)
        obj = self.state.casts.ptr(obj)
        obj_size = self.state.casts.size_t(obj_size)
        active_backends = self.state.casts.ptr(active_backends)
        chosen_backend = self.state.casts.ptr(chosen_backend)
        time = self.state.casts.uint64_t(time)
        print(  f"!!! cht_find_preferred_available_backend [obj: {obj}, obj_size: {obj_size}, " +
                f"active_backends: {active_backends}, chosen_backend: {chosen_backend}]" )

        # Preconditions
        cht = self.state.metadata.get(Cht, cht)
        active_backends = self.state.metadata.get(Pool, active_backends)
        self.state.memory.load(chosen_backend, self.state.sizes.size_t // 8)
        self.state.solver.add(cht.backend_capacity <= active_backends.size)

        # Postconditions
        backend = claripy.BVS("backend", self.state.sizes.size_t)
        def case_true(state):
            print("!!! cht_find_preferred_available_backend: did not find available backend")
            return claripy.BVV(0, self.state.sizes.bool)
        def case_false(state):
            print("!!! cht_find_preferred_available_backend: found available backend")
            state.memory.store(chosen_backend, backend, endness=self.state.arch.memory_endness)
            state.solver.add(0 <= backend, backend < cht.backend_capacity)
            state.solver.add(state.maps.get(active_backends.items, backend)[1])
            return claripy.BVV(1, self.state.sizes.bool)

        guard = self.state.maps.forall(active_backends.items, lambda k, v: claripy.Or(k < 0, k >= cht.backend_capacity))
        return utils.fork_guarded(self, self.state, guard, case_true, case_false)
