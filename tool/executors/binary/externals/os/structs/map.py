import angr
import claripy
import executors.binary.bitsizes as bitsizes
import executors.binary.cast as cast
import executors.binary.utils as utils
from collections import namedtuple


# predicate mapp(struct os_map* map, uint64_t key_size, uint64_t capacity, list<pair<list<char>, uint64_t> > values, list<pair<void*, list<char> > > addrs);
Map = namedtuple('mapp', ['key_size', 'capacity', 'values', 'addrs'])

# struct os_map* os_map_init(uint64_t key_size, uint64_t capacity);
# requires 0 < capacity &*& capacity <= MAP_CAPACITY_MAX &*&
#          0 < key_size;
# ensures result == 0 ? true : mapp(result, key_size, capacity, nil, nil);
class MapInit(angr.SimProcedure):
  def run(self, key_size, capacity):
    # Casts
    key_size = cast.u64(key_size)
    capacity = cast.u64(capacity)
    print("!!! map init", key_size, capacity)

    # Symbolism assumptions
    if key_size.symbolic:
      raise "key_size cannot be symbolic"

    # Preconditions
    if utils.can_be_false(self.state.solver, capacity.UGT(0)):
      raise "Precondition does not hold: 0 < capacity"
    if utils.can_be_false(self.state.solver, key_size.UGT(0)):
      raise "Precondition does not hold: 0 < key_size"

    # Postconditions
    def case_true(state):
      print("!!! map init return 0")
      return 0
    def case_false(state):
      print("!!! map init return nonzero")
      result = state.memory.allocate_opaque("os_map")
      values = state.maps.new(key_size * 8, bitsizes.UINT64_T, name="map_values") # key_size is in bytes
      addrs = state.maps.new(key_size * 8, bitsizes.PTR, name="map_addrs") # key_size is in bytes
      state.metadata.set(result, Map(key_size, capacity, values, addrs))
      return result
    return utils.fork_always(self, case_true, case_false)

# bool os_map_get(struct os_map* map, void* key_ptr, uint64_t* value_out);
# requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
#          chars(key_ptr, key_size, ?key) &*&
#          *value_out |-> _;
# ensures mapp(map, key_size, capacity, values, addrs) &*&
#         chars(key_ptr, key_size, key) &*&
#         switch(map_item_keyed(key, values)) {
#           case none: return result == false &*& *value_out |-> _;
#           case some(v): return result == true &*& *value_out |-> v;
#         };
class MapGet(angr.SimProcedure):
  def run(self, map, key_ptr, value_out):
    # Casts
    map = cast.ptr(map)
    key_ptr = cast.ptr(key_ptr)
    value_out = cast.ptr(value_out)
    print("!!! map get", map, key_ptr, value_out)

    # Symbolism assumptions
    if value_out.symbolic:
      raise "value_out cannot be symbolic"

    # Preconditions
    mapp = self.state.metadata.get(Map, map)
    key = self.state.memory.load(key_ptr, mapp.key_size)
    print("!!! map get key", key)
    _ = self.state.mem[value_out].uint64_t.resolved

    # Postconditions
    def case_has(state, v):
      print("!!! map get has", v)
      state.mem[value_out].uint64_t = v
      return claripy.BVV(1, bitsizes.BOOL)
    def case_not(state):
      print("!!! map get not")
      return claripy.BVV(0, bitsizes.BOOL)
    return utils.fork_guarded_has(self, mapp.values, key, case_has, case_not)

# void os_map_set(struct os_map* map, void* key_ptr, uint64_t value);
# requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
#          [0.25]chars(key_ptr, key_size, ?key) &*&
#          length(values) < capacity &*&
#          map_item_keyed(key, values) == none &*&
#          map_item_keyed(key, addrs) == none;
# ensures mapp(map, key_size, capacity, ?new_values, ?new_addrs) &*&
#         length(new_values) == length(values) + 1 &*&
#         true == subset(values, new_values) &*&
#         map_item_keyed(key, new_values) == some(value)
#         length(new_addrs) == length(addrs) + 1 &*&
#         true == subset(addrs, new_addrs) &*&
#         map_item_keyed(key, new_addrs) == some(key_ptr);
class MapSet(angr.SimProcedure):
  def run(self, map, key_ptr, value):
    # Casts
    map = cast.ptr(map)
    key_ptr = cast.ptr(key_ptr)
    value = cast.u64(value)
    print("!!! map put", map, key_ptr, value)

    # Preconditions
    mapp = self.state.metadata.get(Map, map)
    key = self.state.memory.load(key_ptr, mapp.key_size)
    print("!!! map put key", key)
    self.state.memory.take(25, key_ptr, mapp.key_size)
    if utils.can_be_false(self.state.solver, self.state.maps.length(mapp.values).ULT(mapp.capacity)):
      raise "Precondition does not hold: length(values) < capacity"
    if utils.can_be_false(self.state.solver, claripy.Not(self.state.maps.get(mapp.values, key)[1])):
      raise "Precondition does not hold: map_item_keyed(key, values) == none"
    if utils.can_be_false(self.state.solver, claripy.Not(self.state.maps.get(mapp.addrs, key)[1])):
      raise "Precondition does not hold: map_item_keyed(key, addrs) == none"

    # Postconditions
    self.state.maps.set(mapp.values, key, value)
    self.state.maps.set(mapp.addrs, key, key_ptr)

# void os_map_remove(struct os_map* map, void* key_ptr);
# requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
#          [?frac]chars(key_ptr, key_size, ?key) &*&
#          frac != 0.0 &*&
#          map_item_keyed(key, values) != none &*&
#          map_item_keyed(key, addrs) == some(key_ptr);
# ensures mapp(map, key_size, capacity, ?new_values, ?new_addrs) &*&
#         length(new_values) == length(values) - 1 &*&
#         true == subset(new_values, values) &*&
#         map_item_keyed(key, new_values) == none &*&
#         length(new_addrs) == length(addrs) - 1 &*&
#         true == subset(new_addrs, addrs) &*&
#         map_item_keyed(key, new_addrs) == none &*&
#         [frac + 0.25]chars(key_ptr, key_size, key);
class MapRemove(angr.SimProcedure):
  def run(self, map, key_ptr):
    # Casts
    map = cast.ptr(map)
    key_ptr = cast.ptr(key_ptr)
    print("!!! map erase", map, key_ptr)

    # Preconditions
    mapp = self.state.metadata.get(Map, map)
    key = self.state.memory.load(key_ptr, mapp.key_size)
    frac = self.state.memory.take(None, key_ptr, mapp.key_size)
    if utils.can_be_false(self.state.solver, self.state.maps.get(mapp.values, key)[1]):
      raise "Precondition does not hold: map_item_keyed(key, values) != none"
    (key_ptr2, key_ptr2_present) = self.state.maps.get(mapp.addrs, key)
    if utils.can_be_false(self.state.solver, key_ptr2_present) or utils.can_be_false(self.state.solver, key_ptr2 == key_ptr):
      raise "Precondition does not hold: map_item_keyed(key, addrs) == some(key_ptr)"

    # Postconditions
    self.state.maps.remove(mapp.values, key)
    self.state.maps.remove(mapp.addrs, key)
    self.state.memory.give(frac + 25, key_ptr, mapp.key_size)
