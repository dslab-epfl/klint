import angr
import claripy
import executors.binary.bitsizes as bitsizes
import executors.binary.cast as cast
import executors.binary.clock as clock
import executors.binary.utils as utils
from collections import namedtuple

# predicate poolp(struct os_pool* pool, size_t size, list<pair<size_t, time_t> > items);
Pool = namedtuple('poolp', ['size', 'items'])

# struct os_pool* os_pool_alloc(size_t size);
# requires size <= (SIZE_MAX / 16) - 2;
# ensures poolp(result, size, nil);
class OsPoolAlloc(angr.SimProcedure):
    def run(self, size):
        # Casts
        index_range = cast.size_t(size)
        print("!!! os_pool_alloc", size)

        # Preconditions
        if utils.can_be_false(self.state.solver, size <= ((2 ** bitsizes.SIZE_T) // 16) - 2):
            raise "Precondition does not hold: size <= (SIZE_MAX / 16) - 2"

        # Postconditions
        result = self.state.memory.allocate_opaque("os_pool")
        items = self.state.maps.new(bitsizes.SIZE_T, bitsizes.TIME_T, name="pool_items")
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
            raise "out_index cannot be symbolic"

        # Preconditions
        poolp = self.state.metadata.get(Pool, pool)
        clock.assert_is_current_time(self.state, time) # equivalent to the "upperbounded" precondition; TODO improve this
        _ = self.state.memory.load(out_index, bitsizes.uint64_t)

        # Postconditions
        index = claripy.BVS("index", bitsizes.SIZE_T)
        self.state.add_constraints(index < dchainp.size)
        self.state.memory.store(out_index, index)
        def case_true(state):
            print("!!! os_pool_borrow full")
            return claripy.BVV(0, bitsizes.BOOL)
        def case_false(state):
            print("!!! os_pool_borrow notfull", index)
            state.add_constraints(claripy.Not(state.maps.get(poolp.items, index)[1]))
            if not state.satisfiable():
                raise "Could not add constraint: ghostmap_get(items, index) == none"
            state.maps.set(poolp.items, index, time)
            return claripy.BVV(1, bitsizes.BOOL)
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
        poolp = self.state.metadata.get(Pool, poolp)
        if utils.can_be_false(self.state.solver, index < poolp.size):
            raise "Precondition does not hold: index < size"
        if utils.can_be_false(self.state.solver, self.state.maps.get(poolp.items, index)[1]):
            raise "Precondition does not hold: ghostmap_get(items, index) != none"

        # Postconditions
        self.state.maps.remove(poolp.items, index)

#void os_pool_refresh(struct os_pool* pool, time_t time, size_t index);
# requires poolp(pool, ?size, ?items) &*&
#          true == ghostmap_forall(items, (pool_upperbounded)(time)) &*&
#          index < size &*&
#          ghostmap_get(items, index) != none;
# ensures poolp(pool, size, ghostmap_set(ghostmap_remove(items, index), index, time));
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
      raise "Precondition does not hold: index < size"
    if utils.can_be_false(self.state.solver, self.state.maps.get(poolp.items, index)[1]):
      raise "Precondition does not hold: ghostmap_get(items, index) != none"

    # Postconditions
    self.state.maps.set(dchainp.items, index, time)

# bool os_dchain_expire(struct os_dchain* dchain, time_t time, uint64_t* index_out);
# requires dchainp(dchain, ?index_range, ?items) &*&
#          *index_out |-> _;
# ensures *index_out |-> ?index &*&
#         0 <= index &*& index < index_range &*&
#         dchain_items_lowerbounded(items, time) ? (result == false &*&
#                                                   dchainp(dchain, index_range, items))
#                                                : (result == true &*&
#                                                   dchain_items_keyed(index, items) == some(?old) &*&
#                                                   old < time &*&
#                                                   dchainp(dchain, index_range, ?new_items) &*&
#                                                   new_time_opts == dchain_items_remove(index, items));
class DChainExpire(angr.SimProcedure):
  def run(self, dchain, time, index_out):
    # Casts
    dchain = cast.ptr(dchain)
    time = cast.u64(time)
    index_out = cast.ptr(index_out)
    print("!!! dchain expire", dchain, time, index_out)

    # Symbolism assumptions
    if index_out.symbolic:
      raise "index_out cannot be symbolic"

    # Preconditions
    dchainp = self.state.metadata.get(DChain, dchain)
    _ = self.state.mem[index_out].uint64_t.resolved

    # Postconditions
    index = claripy.BVS('index', bitsizes.UINT64_T)
    self.state.add_constraints(index.UGE(0))
    self.state.add_constraints(index.ULT(dchainp.index_range))
    self.state.mem[index_out].uint64_t = index
    def case_true(state):
      print("!!! dchain expire nope")
      return claripy.BVV(0, bitsizes.BOOL)
    def case_false(state):
      print("!!! dchain expire yup", index)
      state.add_constraints(state.maps.get(dchainp.items, index)[1])
      state.add_constraints(state.maps.get(dchainp.items, index)[0].SLT(time))
      if not state.satisfiable():
        raise "Could not add constraint: dchain_items_keyed(index, items) == some(?old) &*& old < time"
      state.maps.remove(dchainp.items, index)
      return claripy.BVV(1, bitsizes.BOOL)
    return utils.fork_guarded(self, self.state.maps.forall(dchainp.items, lambda k, v: v.SGE(time)), case_true, case_false)

#bool os_dchain_get(struct os_dchain* dchain, uint64_t index, time_t* time_out);
# requires dchainp(dchain, ?index_range, ?items) &*&
#          0 <= index &*& index < index_range &*&
#          *time_out |-> _;
# ensures dchainp(dchain, index_range, items) &*&
#         switch (dchain_items_keyed(index, items)) {
#           case none: return result == false &*& *time_out |-> _;
#           case some(t): return result == true &*& *time_out |-> t;
#         };
class DChainGet(angr.SimProcedure):
  def run(self, dchain, index, time_out):
    # Casts
    dchain = cast.ptr(dchain)
    index = cast.u64(index)
    time_out = cast.ptr(time_out)
    print("!!! dchain get", dchain, index, time_out)

    # Symbolism assumptions
    if time_out.symbolic:
      raise "time_out cannot be symbolic"

    # Preconditions
    dchainp = self.state.metadata.get(DChain, dchain)
    if utils.can_be_false(self.state.solver, index.UGE(0)):
      raise "Precondition does not hold: 0 <= index"
    if utils.can_be_false(self.state.solver, index.ULT(dchainp.index_range)):
      raise "Precondition does not hold: index < index_range"
    self.state.memory.load(time_out, bitsizes.TIME_T // 8)

    # Postconditions
    def case_has(state, time):
      print("!!! dchain get has", time)
      state.memory.store(time_out, time) # TODO endiannness (or just commit to time_t -> int64_t and use that in code)
      return claripy.BVV(1, bitsizes.BOOL)
    def case_not(state):
      print("!!! dchain get not")
      return claripy.BVV(0, bitsizes.BOOL)
    return utils.fork_guarded_has(self, dchainp.items, index, case_has, case_not)
