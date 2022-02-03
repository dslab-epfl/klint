import angr
from angr.sim_type import *
import claripy
from collections import namedtuple

from .index_pool import Pool
from kalm import utils

# predicate poolp(struct os_pool* pool, size_t size, list<pair<size_t, time_t> > items);
Cht = namedtuple("chtp", ["cht_height", "backend_capacity"])

MAX_CHT_HEIGHT = 40000

class ChtAlloc(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypeNum(16, False), SimTypeNum(16, False)], SimTypePointer(SimTypeBottom(label="void")), arg_names=["cht_height", "backend_capacity"])

    def run(self, cht_height, backend_capacity):
        # Preconditions
        assert utils.definitely_true(self.state.solver, claripy.And(
            0 < cht_height, cht_height < MAX_CHT_HEIGHT,
            0 < backend_capacity, backend_capacity < cht_height
        ))

        # Postconditions
        result = claripy.BVS("cht", self.state.sizes.ptr)
        self.state.metadata.append(result, Cht(cht_height, backend_capacity))
        print(f"!!! cht_alloc [cht_height: {cht_height}, backend_capcity: {backend_capacity}] -> {result}")
        return result


class ChtFindPreferredAvailableBackend(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction(
            [SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void")), SimTypeLength(False), SimTypePointer(SimTypeNum(16, False)), SimTypePointer(SimTypeNum(16, False)), SimTypeNum(64, False)],
            SimTypeBool(),
            arg_names=["cht", "obj", "obj_size", "active_backends", "chosen_backends", "time"])

    def run(self, cht, obj, obj_size, active_backends, chosen_backend, time):
        print(  f"!!! cht_find_preferred_available_backend [obj: {obj}, obj_size: {obj_size}, " +
                f"active_backends: {active_backends}, chosen_backend: {chosen_backend}]" )

        # Preconditions
        cht = self.state.metadata.get(Cht, cht)
        active_backends = self.state.metadata.get(Pool, active_backends)
        self.state.memory.load(chosen_backend, self.state.sizes.uint16_t // 8)
        assert utils.definitely_true(self.state.solver,
            cht.backend_capacity.zero_extend(self.state.sizes.size_t - self.state.sizes.uint16_t) <= active_backends.size
        )

        # Postconditions
        backend = claripy.BVS("cht_backend", self.state.sizes.uint16_t)
        def case_true(state):
            print("!!! cht_find_preferred_available_backend: did not find available backend")
            return claripy.BVV(0, state.sizes.bool)
        def case_false(state):
            print("!!! cht_find_preferred_available_backend: found available backend")
            state.memory.store(chosen_backend, backend, endness=state.arch.memory_endness)
            state.solver.add(0 <= backend, backend < cht.backend_capacity)
            state.solver.add(state.maps.get(active_backends.items, backend.zero_extend(self.state.sizes.size_t - self.state.sizes.uint16_t))[1])
            return claripy.BVV(1, state.sizes.bool)

        guard = self.state.maps.forall(active_backends.items, lambda k, v: claripy.Or(k < 0, k >= cht.backend_capacity.zero_extend(self.state.sizes.size_t - self.state.sizes.uint16_t)))
        return utils.fork_guarded(self, self.state, guard, case_true, case_false)
