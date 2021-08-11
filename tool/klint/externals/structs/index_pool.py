import angr
import claripy
from collections import namedtuple

from kalm import utils


# predicate poolp(struct index_pool* pool, size_t size, time_t expiration_time, list<pair<size_t, time_t> > items);
Pool = namedtuple('poolp', ['size', 'expiration_time', 'items'])

# struct index_pool* index_pool_alloc(size_t size, time_t expiration_time);
# requires size * sizeof(time_t) <= SIZE_MAX;
# ensures poolp(result, size, expiration_time, nil);
class index_pool_alloc(angr.SimProcedure):
    def run(self, size, expiration_time):
        # Casts
        size = self.state.casts.size_t(size)
        expiration_time = self.state.casts.uint64_t(expiration_time)

        # Preconditions
        assert utils.definitely_true(self.state.solver, 
            ((size * self.state.sizes.uint64_t).ULE(2 ** self.state.sizes.size_t - 1))
        )

        # Postconditions
        result = claripy.BVS("index_pool", self.state.sizes.ptr)
        items = self.state.maps.new(self.state.sizes.size_t, self.state.sizes.uint64_t, "pool_items")
        self.state.metadata.append(result, Pool(size, expiration_time, items))
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
        pool = self.state.casts.ptr(pool)
        time = self.state.casts.uint64_t(time)
        out_index = self.state.casts.ptr(out_index)
        out_used = self.state.casts.ptr(out_used)
        print("!!! index_pool_borrow", pool, time, out_index, out_used)

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        assert utils.definitely_true(self.state.solver,
            time != 0xFF_FF_FF_FF_FF_FF_FF_FF
        )
        self.state.memory.load(out_index, self.state.sizes.size_t // 8)
        self.state.memory.load(out_used, self.state.sizes.bool // 8)

        # Postconditions
        index = claripy.BVS("index", self.state.sizes.size_t)
        used = claripy.BVS("used", self.state.sizes.bool)
        self.state.memory.store(out_index, index, endness=self.state.arch.memory_endness)
        self.state.memory.store(out_used, used, endness=self.state.arch.memory_endness)

        result = claripy.BVS("borrow_result", self.state.sizes.bool)
        self.state.solver.add(
            claripy.If(
                self.state.maps.length(poolp.items) == poolp.size,
                claripy.If(
                    self.state.maps.forall(poolp.items, lambda k, v: time.ULT(poolp.expiration_time) | (time - poolp.expiration_time).ULE(v)),
                    result == claripy.BVV(0, self.state.sizes.bool),
                    (result != claripy.BVV(0, self.state.sizes.bool)) & (used != claripy.BVV(0, self.state.sizes.bool))
                ),
                result != claripy.BVV(0, self.state.sizes.bool)
            )
        )
        def case_true(state):
            print("!!! index_pool_borrow true")
            state.solver.add(
                index.ULT(poolp.size),
                claripy.If(
                    used != claripy.BVV(0, state.sizes.bool),
                    state.maps.get(poolp.items, index)[1] & ~(time.ULT(poolp.expiration_time) | (time - poolp.expiration_time).ULE(state.maps.get(poolp.items, index)[0])),
                    ~(state.maps.get(poolp.items, index)[1])
                )
            )
            state.maps.set(poolp.items, index, time)
            return result

        def case_false(state):
            print("!!! index_pool_borrow false")
            return result

        return utils.fork_guarded(self, self.state, result != claripy.BVV(0, self.state.sizes.bool), case_true, case_false)

# void index_pool_refresh(struct index_pool* pool, time_t time, size_t index);
# requires poolp(pool, ?size, ?exp_time, ?items) &*&
#          time != TIME_MAX &*&
#          index < size;
# ensures poolp(pool, size, exp_time, ghostmap_set(items, index, time));
class index_pool_refresh(angr.SimProcedure):
    def run(self, pool, time, index):
        # Casts
        pool = self.state.casts.ptr(pool)
        time = self.state.casts.uint64_t(time)
        index = self.state.casts.size_t(index)
        print("!!! index_pool_refresh", pool, time, index)

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        assert utils.definitely_true(self.state.solver, claripy.And(
            time != 0xFF_FF_FF_FF_FF_FF_FF_FF,
            index < poolp.size
        ))

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
        pool = self.state.casts.ptr(pool)
        time = self.state.casts.uint64_t(time)
        index = self.state.casts.size_t(index)
        print("!!! index_pool_used", pool, index, time)

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)

        # Postconditions
        def case_has(state, t):
            print("!!! index_pool_used has", time)
            def case_true(state):
                return claripy.BVV(1, state.sizes.bool)
            def case_false(state):
                return claripy.BVV(0, state.sizes.bool)
            return utils.fork_guarded(self, state, time.ULT(poolp.expiration_time) | (time - poolp.expiration_time).ULE(t), case_true, case_false)

        def case_not(state):
            print("!!! index_pool_used not")
            return claripy.BVV(0, state.sizes.bool)

        return utils.fork_guarded_has(self, self.state, poolp.items, index, case_has, case_not)

# void index_pool_return(struct index_pool* pool, size_t index);
# requires poolp(pool, ?size, ?exp_time, ?items) &*&
#          index < size;
# ensures poolp(pool, size, exp_time, ghostmap_remove(items, index));
class index_pool_return(angr.SimProcedure):
    def run(self, pool, index):
        # Casts
        pool = self.state.casts.ptr(pool)
        index = self.state.casts.size_t(index)
        print("!!! index_pool_return", pool, index)

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        assert utils.definitely_true(self.state.solver,
            index < poolp.size
        )

        # Postconditions
        self.state.maps.remove(poolp.items, index)
