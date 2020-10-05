# Standard/External libraries
import angr
import claripy
from collections import namedtuple

# Us
import binary.bitsizes as bitsizes
import binary.cast as cast
import binary.clock as clock
import binary.utils as utils
from binary.exceptions import SymbexException

# predicate poolp(struct os_pool* pool, size_t size, list<pair<size_t, time_t> > items);
Pool = namedtuple('poolp', ['size', 'items'])

# struct os_pool* os_pool_alloc(size_t size);
# requires size <= (SIZE_MAX / 16) - 2;
# ensures poolp(result, size, nil);
class OsPoolAlloc(angr.SimProcedure):
    def run(self, size):
        # Casts
        size = cast.size_t(size)
        print("!!! os_pool_alloc", size)

        # Preconditions
        if utils.can_be_false(self.state.solver, size <= (((2 ** bitsizes.size_t - 1) // 16) - 2)):
            raise SymbexException("Precondition does not hold: size <= (SIZE_MAX / 16) - 2")

        # Postconditions
        result = self.state.memory.allocate_opaque("os_pool")
        items = self.state.maps.new(bitsizes.size_t, bitsizes.int64_t, name="pool_items")
        self.state.metadata.set(result, Pool(size, items))
        return result


# bool os_pool_borrow(struct os_pool* pool, time_t time, size_t* out_index);
# requires poolp(pool, ?size, ?items) &*&
#          true == ghostmap_forall(items, (pool_upperbounded)(time)) &*&
#          *out_index |-> _;
# ensures *out_index |-> ?index &*&
#         index < size &*&
#         length(items) == size ? (result == false &*&
#                                  poolp(pool, size, items))
#                               : (result == true &*&
#                                  ghostmap_get(items, index) == none &*&
#                                  poolp(pool, size, ghostmap_set(items, index, time)));
class OsPoolBorrow(angr.SimProcedure):
    def run(self, pool, time, out_index):
        # Casts
        pool = cast.ptr(pool)
        time = cast.int64_t(time)
        out_index = cast.ptr(out_index)
        print("!!! os_pool_borrow", pool, time, out_index)

        # Symbolism assumptions
        if out_index.symbolic:
            raise SymbexException("out_index cannot be symbolic") 

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        clock.assert_is_current_time(self.state, time) # equivalent to the "upperbounded" precondition; TODO improve this
        _ = self.state.memory.load(out_index, bitsizes.size_t // 8)

        # Postconditions
        index = claripy.BVS("index", bitsizes.size_t)
        self.state.add_constraints(index < poolp.size)
        self.state.memory.store(out_index, index, endness=self.state.arch.memory_endness)
        def case_true(state):
            print("!!! os_pool_borrow full")
            return claripy.BVV(0, bitsizes.bool)
        def case_false(state):
            print("!!! os_pool_borrow notfull", index)
            utils.add_constraints_and_check_sat(state, claripy.Not(state.maps.get(poolp.items, index)[1]))
            state.maps.set(poolp.items, index, time)
            return claripy.BVV(1, bitsizes.bool)
        return utils.fork_guarded(self, self.state.maps.length(poolp.items) == poolp.size, case_true, case_false)

# void os_pool_return(struct os_pool* pool, size_t index);
# requires poolp(pool, ?size, ?items) &*&
#          index < size &*&
#          ghostmap_get(items, index) != none;
# ensures poolp(pool, size, ghostmap_remove(items, index));
class OsPoolReturn(angr.SimProcedure):
    def run(self, pool, index):
        # Casts
        pool = cast.ptr(pool)
        index = cast.size_t(index)
        print("!!! os_pool_return", pool, index)

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        if utils.can_be_false(self.state.solver, index < poolp.size):
            raise SymbexException("Precondition does not hold: index < size")
        if utils.can_be_false(self.state.solver, self.state.maps.get(poolp.items, index)[1]):
            raise SymbexException("Precondition does not hold: ghostmap_get(items, index) != none")

        # Postconditions
        self.state.maps.remove(poolp.items, index)

# void os_pool_refresh(struct os_pool* pool, time_t time, size_t index);
# requires poolp(pool, ?size, ?items) &*&
#          true == ghostmap_forall(items, (pool_upperbounded)(time)) &*&
#          index < size &*&
#          ghostmap_get(items, index) != none;
# ensures poolp(pool, size, ghostmap_set(items, index, time));
class OsPoolRefresh(angr.SimProcedure):
    def run(self, pool, time, index):
        # Casts
        pool = cast.ptr(pool)
        time = cast.int64_t(time)
        index = cast.size_t(index)
        print("!!! os_pool_refresh", pool, time, index)

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        clock.assert_is_current_time(self.state, time) # equivalent to the "upperbounded" precondition; TODO improve this
        if utils.can_be_false(self.state.solver, index < poolp.size):
            raise SymbexException("Precondition does not hold: index < size")
        if utils.can_be_false(self.state.solver, self.state.maps.get(poolp.items, index)[1]):
            raise SymbexException("Precondition does not hold: ghostmap_get(items, index) != none")

        # Postconditions
        self.state.maps.set(poolp.items, index, time)


# bool os_pool_used(struct os_pool* pool, size_t index, time_t* out_time);
# requires poolp(pool, ?size, ?items) &*&
#          index < size &*&
#          *out_time |-> _;
# ensures poolp(pool, size, items) &*&
#         switch (ghostmap_get(items, index)) {
#           case none: return result == false &*& *out_time |-> _;
#           case some(t): return result == true &*& *out_time |-> t;
#         };
class OsPoolUsed(angr.SimProcedure):
    def run(self, pool, index, out_time):
        # Casts
        pool = cast.ptr(pool)
        index = cast.size_t(index)
        out_time = cast.ptr(out_time)
        print("!!! os_pool_used", pool, index, out_time)

        # Symbolism assumptions
        if out_time.symbolic:
            raise SymbexException("out_time cannot be symbolic")

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        if utils.can_be_false(self.state.solver, index < poolp.size):
            raise SymbexException("Precondition does not hold: index < size")
        self.state.memory.load(out_time, bitsizes.int64_t // 8)

        # Postconditions
        def case_has(state, time):
            print("!!! os_pool_used has", time)
            state.memory.store(out_time, time, endness=self.state.arch.memory_endness)
            return claripy.BVV(1, bitsizes.bool)
        def case_not(state):
            print("!!! os_pool_used not")
            return claripy.BVV(0, bitsizes.bool)
        return utils.fork_guarded_has(self, poolp.items, index, case_has, case_not)

# bool os_pool_expire(struct os_pool* pool, time_t time, size_t* out_index);
# requires poolp(pool, ?size, ?items) &*&
#          *out_index |-> _;
# ensures *out_index |-> ?index &*&
#         index < size &*&
#         ghostmap_forall(items, (pool_lowerbounded)(time)) ? (result == false &*&
#                                                              poolp(pool, size, items))
#                                                           : (result == true &*&
#                                                              ghostmap_get(items, index) == some(?old) &*&
#                                                              old < time &*&
#                                                              poolp(pool, size, ghostmap_remove(items, index)));
class OsPoolExpire(angr.SimProcedure):
    def run(self, pool, time, out_index):
        # Casts
        pool = cast.ptr(pool)
        time = cast.int64_t(time)
        out_index = cast.ptr(out_index)
        print("!!! os_pool_expire", pool, time, out_index)

        # Symbolism assumptions
        if out_index.symbolic:
            raise SymbexException("out_index cannot be symbolic") 

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        self.state.memory.load(out_index, bitsizes.size_t // 8)

        # Postconditions
        index = claripy.BVS('index', bitsizes.size_t)
        self.state.add_constraints(index < poolp.size)
        self.state.memory.store(out_index, index, endness=self.state.arch.memory_endness)
        def case_true(state):
            print("!!! os_pool_expire none")
            return claripy.BVV(0, bitsizes.bool)
        def case_false(state):
            print("!!! os_pool_expire some", index)
            utils.add_constraints_and_check_sat(state,
                state.maps.get(poolp.items, index)[1],
                state.maps.get(poolp.items, index)[0].SLT(time)
            )
            state.maps.remove(poolp.items, index)
            return claripy.BVV(1, bitsizes.bool)
        return utils.fork_guarded(self, self.state.maps.forall(poolp.items, lambda k, v: v.SGE(time)), case_true, case_false)
