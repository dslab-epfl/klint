import angr
import executors.binary.bitsizes as bitsizes
import executors.binary.cast as cast
import executors.binary.clock as clock
import executors.binary.utils as utils
from collections import namedtuple


# predicate dchainp(struct os_dchain* dchain, uint64_t index_range, list<pair<uint64_t, time_t> > items);
DChain = namedtuple('dchainp', ['index_range', 'items'])

# struct os_dchain* os_dchain_init(uint64_t index_range);
# requires 0 < index_range &*& index_range <= DCHAIN_RANGE_MAX;
# ensures result == 0 ? true : dchainp(result, index_range, nil);
class DChainInit(angr.SimProcedure):
  def run(self, index_range):
    # Casts
    index_range = cast.u64(index_range)
    print("!!! dchain init", index_range)

    # Preconditions
    if utils.can_be_false(self.state.solver, index_range.UGT(0)):
      raise "Precondition does not hold: 0 < index_range"

    # Postconditions
    def case_true(state):
      print("!!! dchain init return 0")
      return 0
    def case_false(state):
      print("!!! dchain init return nonzero")
      result = state.memory.allocate_opaque("os_dchain")
      items = state.maps.allocate(bitsizes.UINT64_T, bitsizes.TIME_T, name="dchain_items")
      state.metadata.set(result, DChain(index_range, items))
      return result
    return utils.fork_always(self, case_true, case_false)

# bool os_dchain_add(struct os_dchain* dchain, time_t time, uint64_t* index_out);
# requires dchainp(dchain, ?index_range, ?items) &*&
#          true == dchain_items_upperbounded(items, time) &*&
#          *index_out |-> _;
# ensures *index_out |-> ?index &*&
#          0 <= index &*& index < index_range &*&
#          length(items) == index_range ? (result == false &*&
#                                          dchainp(dchain, index_range, items))
#                                       : (result == true &*&
#                                          dchain_items_keyed(index, items) == none &*&
#                                          dchainp(dchain, index_range, ?new_items) &*&
#                                          true == subset(items, new_items) &*&
#                                          length(new_items) == length(items) + 1 &*&
#                                          dchain_items_keyed(index, new_items) == some(time));
class DChainAdd(angr.SimProcedure):
  def run(self, dchain, time, index_out):
    # Casts
    dchain = cast.ptr(dchain)
    time = cast.i64(time)
    index_out = cast.ptr(index_out)
    print("!!! dchain add", dchain, time, index_out)

    # Symbolism assumptions
    if index_out.symbolic:
      raise "index_out cannot be symbolic"

    # Preconditions
    dchainp = self.state.metadata.get(DChain, dchain)
    clock.assert_is_current_time(self.state, time)
    _ = self.state.mem[index_out].uint64_t.resolved

    # Postconditions
    index = self.state.solver.BVS("index", bitsizes.UINT64_T)
    self.state.add_constraints(index.UGE(0))
    self.state.add_constraints(index.ULT(dchainp.index_range))
    self.state.mem[index_out].uint64_t = index
    def case_true(state):
      print("!!! dchain add full")
      return state.solver.BVV(0, bitsizes.BOOL)
    def case_false(state):
      print("!!! dchain add has space", index)
      state.add_constraints(state.solver.Not(state.maps.get(dchainp.items, index)[1]))
      if not state.satisfiable():
        raise "Could not add constraint: dchain_items_keyed(index, items) == none"
      state.maps.add(dchainp.items, index, time)
      return state.solver.BVV(1, bitsizes.BOOL)
    return utils.fork_guarded(self, self.state.maps.length(dchainp.items) == dchainp.index_range, case_true, case_false)

# void os_dchain_refresh(struct os_dchain* dchain, time_t time, uint64_t index);
# requires dchainp(dchain, ?index_range, ?items) &*&
#          true == dchain_items_upperbounded(items, time) &*&
#          0 <= index &*& index < index_range &*&
#          dchain_items_keyed(index, items) != none;
# ensures dchainp(dchain, index_range, ?new_items) &*&
#         new_items == dchain_items_update(index, time, items);
class DChainRefresh(angr.SimProcedure):
  def run(self, dchain, time, index):
    # Casts
    dchain = cast.ptr(dchain)
    time = cast.i64(time)
    index = cast.u64(index)
    print("!!! dchain refresh", dchain, time, index)

    # Preconditions
    dchainp = self.state.metadata.get(DChain, dchain)
    clock.assert_is_current_time(self.state, time)
    if utils.can_be_false(self.state.solver, index.UGE(0)):
      raise "Precondition does not hold: 0 <= index"
    if utils.can_be_false(self.state.solver, index.ULT(dchainp.index_range)):
      raise "Precondition does not hold: index < index_range"
    if utils.can_be_false(self.state.solver, self.state.maps.get(dchainp.items, index)[1]):
      raise "Precondition does not hold: dchain_items_keyed(index, items) != none"

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
    index = self.state.solver.BVS('index', bitsizes.UINT64_T)
    self.state.add_constraints(index.UGE(0))
    self.state.add_constraints(index.ULT(dchainp.index_range))
    self.state.mem[index_out].uint64_t = index
    def case_true(state):
      print("!!! dchain expire nope")
      return state.solver.BVV(0, bitsizes.BOOL)
    def case_false(state):
      print("!!! dchain expire yup", index)
      state.add_constraints(state.maps.get(dchainp.items, index)[1])
      state.add_constraints(state.maps.get(dchainp.items, index)[0].SLT(time))
      if not state.satisfiable():
        raise "Could not add constraint: dchain_items_keyed(index, items) == some(?old) &*& old < time"
      state.maps.remove(dchainp.items, index)
      return state.solver.BVV(1, bitsizes.BOOL)
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
      return state.solver.BVV(1, bitsizes.BOOL)
    def case_not(state):
      print("!!! dchain get not")
      return state.solver.BVV(0, bitsizes.BOOL)
    return utils.fork_guarded_has(self, dchainp.items, index, case_has, case_not)

# TODO update this
#// only used in load balancer
#//void os_dchain_remove(struct os_dchain* dchain, int index);
#///*@ requires dchainp(dchain, ?index_range, ?items) &*&
#//             0 <= index &*& index < index_range &*&
#//             dchain_items_keyed(index, items) != none; @*/
#///*@ ensures dchainp(dchain, index_range, ?new_items) &*&
#//            new_items == dchain_items_remove(index, items); @*/
#class DChainRemove(angr.SimProcedure):
#  def run(self, dchain, index):
#    # Casts
#    dchain = cast.ptr(dchain)
#    index = cast.int(index)
#
#    # Preconditions
#    dchainp = self.state.metadata.get(DChain, dchain)
#    if utils.can_be_false(self.state.solver, index.SGE(0)):
#      raise "Precondition does not hold: 0 <= index"
#    if utils.can_be_false(self.state.solver, index.SLT(self.state.aarrays.length(dchainp.time_opts_present))):
#      raise "Precondition does not hold: index < length(time_opts)"
#
#    # Postconditions
#    self.state.aarrays.set(dchainp.time_opts_present, index, self.state.solver.BVV(0, 1))
#    self.state.aarrays.set(dchainp.time_opts_values, index, self.state.solver.BVV(2**bitsizes.TIME_T-1, bitsizes.TIME_T))
