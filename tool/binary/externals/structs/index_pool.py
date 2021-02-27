# Standard/External libraries
import angr
import claripy
from collections import namedtuple

# Us
import binary.bitsizes as bitsizes
import binary.cast as cast
import binary.utils as utils
from binary.exceptions import SymbexException


# predicate poolp(struct index_pool* pool, size_t size, time_t expiration_time, list<pair<size_t, time_t> > items);
Pool = namedtuple('poolp', ['size', 'expiration_time', 'items'])

# struct index_pool* index_pool_alloc(size_t size, time_t expiration_time);
# requires size * sizeof(time_t) <= SIZE_MAX;
# ensures poolp(result, size, expiration_time, nil);
class index_pool_alloc(angr.SimProcedure):
    def run(self, size, expiration_time):
        # Casts
        size = cast.size_t(size)
        expiration_time = cast.uint64_t(expiration_time)

        # Preconditions
        if utils.can_be_false(self.state.solver, (size * bitsizes.uint64_t).ULE(2 ** bitsizes.size_t - 1)):
            raise SymbexException("Precondition does not hold: size * sizeof(time_t) <= SIZE_MAX")

        # Postconditions
        result = self.state.memory.allocate_opaque("index_pool")
        items = self.state.maps.new(bitsizes.size_t, bitsizes.uint64_t, "pool_items")
        self.state.metadata.set(result, Pool(size, expiration_time, items))
        print("!!! index_pool_alloc", size, "->", result)
        return result

#bool index_pool_borrow(struct index_pool* pool, time_t time, size_t* out_index, bool* out_used);
# requires poolp(pool, ?size, ?exp_time, ?items) &*&
#          time != TIME_MAX &*&
#          *out_index |-> _ &*&
#          *out_used |-> _;
# ensures *out_index |-> ?index &*&
#         *out_used |-> ?used &*&
#         (length(items) == size ? (ghostmap_forall(items, (pool_young)(time, exp_time)) ? result == false
#                                                                                        : (result == true &*& used == true))
#                                : result == true) &*&
#         result ? poolp(pool, size, exp_time, ghostmap_set(items, index, time)) &*&
#                  index < size &*&
#                  (used ? (ghostmap_get(items, index) == some(?old) &*&
#                           false == pool_young(time, exp_time, index, old))
#                        : (ghostmap_get(items, index) == none))
#                : poolp(pool, size, exp_time, items);
class index_pool_borrow(angr.SimProcedure):
    def run(self, pool, time, out_index, out_used):
        # Casts
        pool = cast.ptr(pool)
        time = cast.int64_t(time)
        out_index = cast.ptr(out_index)
        out_used = cast.ptr(out_used)
        print("!!! index_pool_borrow", pool, time, out_index, out_used)

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        if utils.can_be_false(self.state.solver, time != 0xFF_FF_FF_FF_FF_FF_FF_FF):
            raise SymbexException("Precondition does not hold: time != TIME_MAX")
        self.state.memory.load(out_index, bitsizes.size_t // 8, endness=self.state.arch.memory_endness)
        self.state.memory.load(out_used, bitsizes.bool // 8, endness=self.state.arch.memory_endness)

        # Postconditions
        index = self.state.symbol_factory.BVS("index", bitsizes.size_t)
        used = self.state.symbol_factory.BVS("used", bitsizes.bool)
        self.state.memory.store(out_index, index, endness=self.state.arch.memory_endness)
        self.state.memory.store(out_used, used, endness=self.state.arch.memory_endness)

        result = self.state.symbol_factory.BVS("borrow_result", bitsizes.bool)
        self.state.add_constraints(
            claripy.If(
                self.state.maps.length(poolp.items) == poolp.size,
                claripy.If(
                    self.state.maps.forall(poolp.items, lambda k, v: time.ULT(poolp.expiration_time) | (time - poolp.expiration_time).ULE(v)),
                    result == claripy.BVV(0, bitsizes.bool),
                    (result != claripy.BVV(0, bitsizes.bool)) & (used != claripy.BVV(0, bitsizes.bool))
                ),
                result != claripy.BVV(0, bitsizes.bool)
            )
        )
        def case_true(state):
            print("!!! index_pool_borrow true")
            state.add_constraints(
                index.ULT(poolp.size),
                claripy.If(
                    used != claripy.BVV(0, bitsizes.bool),
                    state.maps.get(poolp.items, index)[1] & ~(time.ULT(poolp.expiration_time) | (time - poolp.expiration_time).ULE(state.maps.get(poolp.items, index)[0])),
                    ~(state.maps.get(poolp.items, index)[1])
                )
            )
            state.maps.set(poolp.items, index, time)
            return result

        def case_false(state):
            print("!!! index_pool_borrow false")
            return result

        return utils.fork_guarded(self, self.state, result != claripy.BVV(0, bitsizes.bool), case_true, case_false)

# void index_pool_refresh(struct index_pool* pool, time_t time, size_t index);
# requires poolp(pool, ?size, ?exp_time, ?items) &*&
#          time != TIME_MAX &*&
#          index < size &*&
#          ghostmap_get(items, index) != none;
# ensures poolp(pool, size, exp_time, ghostmap_set(items, index, time));
class index_pool_refresh(angr.SimProcedure):
    def run(self, pool, time, index):
        # Casts
        pool = cast.ptr(pool)
        time = cast.uint64_t(time)
        index = cast.size_t(index)
        print("!!! index_pool_refresh", pool, time, index)

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        if utils.can_be_false(self.state.solver, time != 0xFF_FF_FF_FF_FF_FF_FF_FF):
            raise SymbexException("Precondition does not hold: time != TIME_MAX")
        if utils.can_be_false(self.state.solver, index < poolp.size):
            raise SymbexException("Precondition does not hold: index < size")
        if utils.can_be_false(self.state.solver, self.state.maps.get(poolp.items, index)[1]):
            raise SymbexException("Precondition does not hold: ghostmap_get(items, index) != none")

        # Postconditions
        self.state.maps.set(poolp.items, index, time)

# bool index_pool_used(struct index_pool* pool, time_t time, size_t index);
# requires poolp(pool, ?size, ?exp_time, ?items);
# ensures poolp(pool, size, exp_time, items) &*&
#         switch (ghostmap_get(items, index)) {
#           case none: return result == false;
#           case some(t): return result == pool_young(time, exp_time, 0, t);
#         };
class index_pool_used(angr.SimProcedure):
    def run(self, pool, time, index):
        # Casts
        pool = cast.ptr(pool)
        time = cast.uint64_t(time)
        index = cast.size_t(index)
        print("!!! index_pool_used", pool, index, time)

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)

        # Postconditions
        def case_has(state, t):
            print("!!! index_pool_used has", time)
            def case_true(state):
                return claripy.BVV(1, bitsizes.bool)
            def case_false(state):
                return claripy.BVV(0, bitsizes.bool)
            return utils.fork_guarded(self, state, time.ULT(poolp.expiration_time) | (time - poolp.expiration_time).ULE(t), case_true, case_false)

        def case_not(state):
            print("!!! index_pool_used not")
            return claripy.BVV(0, bitsizes.bool)

        return utils.fork_guarded_has(self, self.state, poolp.items, index, case_has, case_not)

# void index_pool_return(struct index_pool* pool, size_t index);
# requires poolp(pool, ?size, ?exp_time, ?items) &*&
#          index < size &*&
#          ghostmap_get(items, index) != none;
# ensures poolp(pool, size, exp_time, ghostmap_remove(items, index));
class index_pool_return(angr.SimProcedure):
    def run(self, pool, index):
        # Casts
        pool = cast.ptr(pool)
        index = cast.size_t(index)
        print("!!! index_pool_return", pool, index)

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        if utils.can_be_false(self.state.solver, index < poolp.size):
            raise SymbexException("Precondition does not hold: index < size")
        if utils.can_be_false(self.state.solver, self.state.maps.get(poolp.items, index)[1]):
            raise SymbexException("Precondition does not hold: ghostmap_get(items, index) != none")

        # Postconditions
        self.state.maps.remove(poolp.items, index)