import angr
import claripy
import executors.binary.bitsizes as bitsizes
import executors.binary.cast as cast
import executors.binary.utils as utils
from collections import namedtuple


# predicate mapp(struct os_map* map, size_t key_size, size_t capacity, list<pair<list<char>, void*> > values, list<pair<list<char>, void*> > addrs);
Map = namedtuple('mapp', ['key_size', 'capacity', 'values', 'addrs'])

#struct os_map* os_map_alloc(size_t key_size, size_t capacity);
# requires 0 < capacity &*& capacity <= (SIZE_MAX / 8) &*&
#          (capacity & (capacity - 1)) == 0;
# ensures mapp(result, key_size, capacity, nil, nil);
class OsMapAlloc(angr.SimProcedure):
    def run(self, key_size, capacity):
        # Casts
        key_size = cast.size_t(key_size)
        capacity = cast.size_t(capacity)
        print("!!! os_map_alloc", key_size, capacity)

        # Symbolism assumptions
        if key_size.symbolic:
            raise "key_size cannot be symbolic"

        # Preconditions
        if utils.can_be_false(self.state.solver, 0 < capacity):
            raise "Precondition does not hold: 0 < capacity"
        if utils.can_be_false(self.state.solver, capacity < ((2 ** bitsizes.SIZE_T) // 8)):
            raise "Precondition does not hold: capacity < (SIZE_MAX / 8)"
        if utils.can_be_false(self.state.solver, (capacity & (capacity - 1)) == 0):
            raise "Precondition does not hold:  (capacity & (capacity - 1)) == 0"

        # Postconditions
        result = state.memory.allocate_opaque("os_map")
        values = state.maps.new(key_size * 8, bitsizes.UINT64_T, name="map_values") # key_size is in bytes
        addrs = state.maps.new(key_size * 8, bitsizes.PTR, name="map_addrs") # key_size is in bytes
        state.metadata.set(result, Map(key_size, capacity, values, addrs))
        return result

#bool os_map_get(struct os_map* map, void* key_ptr, void** out_value);
# requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
#          chars(key_ptr, key_size, ?key) &*&
#          *out_value |-> _;
# ensures mapp(map, key_size, capacity, values, addrs) &*&
#         chars(key_ptr, key_size, key) &*&
#         switch(ghostmap_get(values, key)) {
#           case none: return result == false &*& *out_value |-> _;
#           case some(v): return result == true &*& *out_value |-> v;
#         };
class OsMapGet(angr.SimProcedure):
    def run(self, map, key_ptr, out_value):
        # Casts
        map = cast.ptr(map)
        key_ptr = cast.ptr(key_ptr)
        out_value = cast.ptr(out_value)
        print("!!! os_map_get", map, key_ptr, out_value)

        # Symbolism assumptions
        if out_value.symbolic:
            raise "out_value cannot be symbolic"

        # Preconditions
        mapp = self.state.metadata.get(Map, map)
        key = self.state.memory.load(key_ptr, mapp.key_size)
        _ = self.state.memory.load(out_value, bitsizes.SIZE_T)
        print("!!! os_map_get key", key)

        # Postconditions
        def case_has(state, v):
            print("!!! os_map_get has", v)
            self.state.memory.store(out_value, v)
            return claripy.BVV(1, bitsizes.BOOL)
        def case_not(state):
            print("!!! os_map_get not")
            return claripy.BVV(0, bitsizes.BOOL)
        return utils.fork_guarded_has(self, mapp.values, key, case_has, case_not)

#void os_map_set(struct os_map* map, void* key_ptr, void* value);
# requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
#          [0.25]chars(key_ptr, key_size, ?key) &*&
#          length(values) < capacity &*&
#          ghostmap_get(values, key) == none &*&
#          ghostmap_get(addrs, key) == none;
# ensures mapp(map, key_size, capacity, ghostmap_set(values, key, value), ghostmap_set(addrs, key, key_ptr));
class OsMapSet(angr.SimProcedure):
    def run(self, map, key_ptr, value):
        # Casts
        map = cast.ptr(map)
        key_ptr = cast.ptr(key_ptr)
        value = cast.ptr(value)
        print("!!! os_map_put", map, key_ptr, value)

        # Preconditions
        mapp = self.state.metadata.get(Map, map)
        key = self.state.memory.load(key_ptr, mapp.key_size)
        self.state.memory.take(25, key_ptr, mapp.key_size)
        if utils.can_be_false(self.state.solver, self.state.maps.length(mapp.values) < mapp.capacity):
            raise "Precondition does not hold: length(values) < capacity"
        if utils.can_be_false(self.state.solver, claripy.Not(self.state.maps.get(mapp.values, key)[1])):
            raise "Precondition does not hold: ghostmap_get(values, key) == none"
        if utils.can_be_false(self.state.solver, claripy.Not(self.state.maps.get(mapp.addrs, key)[1])):
            raise "Precondition does not hold: ghostmap_get(addrs, key) == none"
        print("!!! os_map_put key", key)

        # Postconditions
        self.state.maps.set(mapp.values, key, value)
        self.state.maps.set(mapp.addrs, key, key_ptr)

#void os_map_remove(struct os_map* map, void* key_ptr);
# requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
#          [?frac]chars(key_ptr, key_size, ?key) &*&
#          frac != 0.0 &*&
#          ghostmap_get(values, key) != none &*&
#          ghostmap_get(addrs, key) == some(key_ptr);
# ensures mapp(map, key_size, capacity, ghostmap_remove(values, key), ghostmap_remove(addrs, key)) &*&
#         [frac + 0.25]chars(key_ptr, key_size, key);
class OsMapRemove(angr.SimProcedure):
    def run(self, map, key_ptr):
        # Casts
        map = cast.ptr(map)
        key_ptr = cast.ptr(key_ptr)
        print("!!! os_map_remove", map, key_ptr)

        # Preconditions
        mapp = self.state.metadata.get(Map, map)
        key = self.state.memory.load(key_ptr, mapp.key_size)
        frac = self.state.memory.take(None, key_ptr, mapp.key_size)
        if utils.can_be_false(self.state.solver, self.state.maps.get(mapp.values, key)[1]):
            raise "Precondition does not hold: ghostmap_get(values, key) != none"
        (key_ptr2, key_ptr2_present) = self.state.maps.get(mapp.addrs, key)
        if utils.can_be_false(self.state.solver, key_ptr2_present) or utils.can_be_false(self.state.solver, key_ptr2 == key_ptr):
            raise "Precondition does not hold: ghostmap_get(addrs, key) == some(key_ptr)"
        print("!!! os_map_remove key", key)

        # Postconditions
        self.state.maps.remove(mapp.values, key)
        self.state.maps.remove(mapp.addrs, key)
        self.state.memory.give(frac + 25, key_ptr, mapp.key_size)
