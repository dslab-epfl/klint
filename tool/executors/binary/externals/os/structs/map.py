import angr
import executors.binary.bitsizes as bitsizes
import executors.binary.cast as cast
import executors.binary.utils as utils
from collections import namedtuple


# inductive map_item = map_item(void* key_addr, list<char> key, uint64_t value);
# predicate mapp(struct os_map* map, uint64_t key_size, uint64_t capacity, list<map_item> items);
Map = namedtuple('mapp', ['key_size', 'capacity', 'items_key_addrs', 'items_values'])

# struct os_map* os_map_init(uint64_t key_size, uint64_t capacity);
# requires 0 < capacity &*& capacity <= MAP_CAPACITY_MAX &*&
#          0 < key_size;
# ensures result == 0 ? true : mapp(result, key_size, capacity, nil);
class MapInit(angr.SimProcedure):
  def run(self, key_size, capacity):
    # Casts
    key_size = cast.u64(key_size)
    capacity = cast.u64(capacity)
    print("!!! map init", key_size, capacity)

    # Symbolism assumptions
    if key_size.symbolic:
      raise angr.AngrExitError("key_size cannot be symbolic")

    # Preconditions
    if utils.can_be_false(self.state.solver, capacity.UGT(0)):
      raise angr.AngrExitError("Precondition does not hold: 0 < capacity")
    if utils.can_be_false(self.state.solver, key_size.UGT(0)):
      raise angr.AngrExitError("Precondition does not hold: 0 < key_size")

    # Postconditions
    def case_true(state):
      print("!!! map init return 0")
      return 0
    def case_false(state):
      print("!!! map init return nonzero")
      result = state.memory.allocate_opaque("os_map")
      items_key_addrs = state.maps.allocate(key_size * 8, bitsizes.PTR, name="map_items_key_addrs") # key_size is in bytes
      items_values = state.maps.allocate(key_size * 8, bitsizes.UINT64_T, name="map_items_values") # key_size is in bytes
      state.metadata.set(result, Map(key_size, capacity, items_key_addrs, items_values))
      return result
    return utils.fork_always(self, case_true, case_false)

# bool os_map_get(struct os_map* map, void* key_ptr, uint64_t* value_out);
# requires mapp(map, ?key_size, ?capacity, ?items) &*&
#          chars(key_ptr, key_size, ?key) &*&
#          *value_out |-> _;
# ensures mapp(map, key_size, capacity, items) &*&
#         chars(key_ptr, key_size, key) &*&
#         *value_out |-> ?value &*&
#         switch(map_item_keyed(key, items)) {
#           case none: return result == false;
#           case some(it): return result == true &*& it == map_item(_, key, value);
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
      raise angr.AngrExitError("value_out cannot be symbolic")

    # Preconditions
    mapp = self.state.metadata.get(Map, map)
    key = self.state.memory.load(key_ptr, mapp.key_size)
    print("!!! map get key", key)
    _ = self.state.mem[value_out].uint64_t.resolved

    # Postconditions
    def case_has(state, item):
      print("!!! map get has", item)
      state.add_constraints(state.maps.get(mapp.items_key_addrs, key)[1])
      state.mem[value_out].uint64_t = item
      return state.solver.BVV(1, bitsizes.BOOL)
    def case_not(state):
      print("!!! map get not")
      state.add_constraints(state.solver.Not(state.maps.get(mapp.items_key_addrs, key)[1]))
      return state.solver.BVV(0, bitsizes.BOOL)
    return utils.fork_guarded_has(self, mapp.items_values, key, case_has, case_not)

# void os_map_put(struct os_map* map, void* key_ptr, uint64_t value);
# requires mapp(map, ?key_size, ?capacity, ?items) &*&
#          [0.25]chars(key_ptr, key_size, ?key) &*&
#          length(items) < capacity &*&
#          map_item_keyed(key, items) == none;
# ensures mapp(map, key_size, capacity, ?new_items) &*&
#         length(new_items) == length(items) + 1 &*&
#         true == subset(items, new_items) &*&
#         map_item_keyed(key, new_items) == some(map_item(key_ptr, key, value));
class MapPut(angr.SimProcedure):
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
    if utils.can_be_false(self.state.solver, self.state.maps.length(mapp.items_key_addrs).ULT(mapp.capacity)):
      raise angr.AngrExitError("Precondition does not hold: length(items) < capacity")
    if utils.can_be_false(self.state.solver, self.state.solver.Not(self.state.maps.get(mapp.items_key_addrs, key)[1])):
      raise angr.AngrExitError("Precondition does not hold: map_item_keyed(key, items) == none")

    # Postconditions
    self.state.maps.add(mapp.items_key_addrs, key, key_ptr)
    self.state.maps.add(mapp.items_values, key, value)

# void os_map_erase(struct os_map* map, void* key_ptr);
# requires mapp(map, ?key_size, ?capacity, ?items) &*&
#          [?frac]chars(key_ptr, key_size, ?key) &*&
#          frac != 0.0 &*&
#          map_item_keyed(key, items) == some(map_item(key_ptr, key, _));
# ensures mapp(map, key_size, capacity, ?new_items) &*&
#         length(new_items) == length(items) - 1 &*&
#         true == subset(new_items, items) &*&
#         map_item_keyed(key, new_items) == none &*&
#         [frac + 0.25]chars(key_ptr, key_size, key);
class MapErase(angr.SimProcedure):
  def run(self, map, key_ptr):
    # Casts
    map = cast.ptr(map)
    key_ptr = cast.ptr(key_ptr)
    print("!!! map erase", map, key_ptr)

    # Preconditions
    mapp = self.state.metadata.get(Map, map)
    key = self.state.memory.load(key_ptr, mapp.key_size)
    frac = self.state.memory.take(None, key_ptr, mapp.key_size)
    if utils.can_be_false(self.state.solver, self.state.maps.get(mapp.items_key_addrs, key)[1]) or utils.can_be_false(self.state.solver, self.state.maps.get(mapp.items_key_addrs, key)[0] == key_ptr):
      raise angr.AngrExitError("Precondition does not hold: map_item_keyed(key, items) == some(map_item(key_ptr, key, _))")

    # Postconditions
    self.state.maps.remove(mapp.items_key_addrs, key)
    self.state.maps.remove(mapp.items_values, key)
    self.state.memory.give(frac + 25, key_ptr, mapp.key_size)
