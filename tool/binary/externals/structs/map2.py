import angr
import claripy
from collections import namedtuple

import binary.bitsizes as bitsizes
import binary.cast as cast
import binary.utils as utils


# predicate mapp2(struct os_map2* map, size_t key_size, size_t value_size, size_t capacity, list<pair<list<char>, list<char> > > items);
Map = namedtuple('mapp', ['key_size', 'value_size', 'capacity', 'items'])

# struct os_map2* os_map2_alloc(size_t key_size, size_t value_size, size_t capacity);
# requires key_size > 0 &*&
#          key_size * capacity * 2 <= SIZE_MAX &*&
#          value_size > 0 &*&
#          value_size * capacity * 2 <= SIZE_MAX &*&
#          capacity * sizeof(size_t) * 2 <= SIZE_MAX;
# ensures mapp2(result, key_size, value_size, capacity, nil);
class OsMap2Alloc(angr.SimProcedure):
    def run(self, key_size, value_size, capacity):
        # Casts
        key_size = cast.size_t(key_size)
        value_size = cast.size_t(value_size)
        capacity = cast.size_t(capacity)

        # Symbolism assumptions
        if key_size.symbolic:
            raise Exception("key_size cannot be symbolic")
        if value_size.symbolic:
            raise Exception("key_size cannot be symbolic")

        # Preconditions
        self.state.solver.add(
            key_size.UGT(0),
            (key_size * capacity * 2).ULE(2 ** bitsizes.size_t - 1),
            value_size.UGT(0),
            (value_size * capacity * 2).ULE(2 ** bitsizes.size_t - 1),
            (capacity * bitsizes.size_t * 2).ULE(2 ** bitsizes.size_t - 1)
        )

        # Postconditions
        result = claripy.BVS("os_map2", bitsizes.ptr)
        items = self.state.maps.new(key_size * 8, value_size * 8, "map_items") # key_size and value_size are in bytes
        self.state.metadata.set(result, Map(key_size, value_size, capacity, items))
        print("!!! os_map2_alloc", key_size, value_size, capacity, "->", result)
        return result

# bool os_map2_get(struct os_map2* map, void* key_ptr, void* out_value_ptr);
# requires mapp2(map, ?key_size, ?value_size, ?capacity, ?items) &*&
#          [?f]chars(key_ptr, key_size, ?key) &*&
#          chars(out_value_ptr, value_size, _);
# ensures mapp2(map, key_size, value_size, capacity, items) &*&
#         [f]chars(key_ptr, key_size, key) &*&
#         switch(ghostmap_get(items, key)) {
#           case none: return result == false &*& chars(out_value_ptr, value_size, _);
#           case some(v): return result == true &*& chars(out_value_ptr, value_size, v);
#         };
class OsMap2Get(angr.SimProcedure):
    def run(self, map, key_ptr, out_value_ptr):
        # Casts
        map = cast.ptr(map)
        key_ptr = cast.ptr(key_ptr)
        out_value_ptr = cast.ptr(out_value_ptr)
        print("!!! os_map2_get", map, key_ptr, out_value_ptr)

        # Preconditions
        mapp = self.state.metadata.get(Map, map)
        key = self.state.memory.load(key_ptr, mapp.key_size, endness=self.state.arch.memory_endness)
        self.state.memory.load(out_value_ptr, mapp.value_size)
        print("!!! os_map2_get key", key)

        # Postconditions
        def case_has(state, v):
            print("!!! os_map2_get has", v)
            self.state.memory.store(out_value_ptr, v, endness=self.state.arch.memory_endness)
            return claripy.BVV(1, bitsizes.bool)
        def case_not(state):
            print("!!! os_map2_get not")
            return claripy.BVV(0, bitsizes.bool)
        return utils.fork_guarded_has(self, self.state, mapp.items, key, case_has, case_not)

# void os_map2_set(struct os_map2* map, void* key_ptr, void* value_ptr);
# requires mapp2(map, ?key_size, ?value_size, ?capacity, ?items) &*&
#          [?kf]chars(key_ptr, key_size, ?key) &*&
#          [?vf]chars(value_ptr, value_size, ?value) &*&
#          ghostmap_get(items, key) == none;
# ensures [kf]chars(key_ptr, key_size, key) &*&
#         [vf]chars(value_ptr, value_size, value) &*&
#         length(items) < capacity ? (result == true &*& mapp2(map, key_size, value_size, capacity, ghostmap_set(items, key, value)))
#                                  : (result == false &*& mapp2(map, key_size, value_size, capacity, items));
class OsMap2Set(angr.SimProcedure):
    def run(self, map, key_ptr, value_ptr):
        # Casts
        map = cast.ptr(map)
        key_ptr = cast.ptr(key_ptr)
        value_ptr = cast.ptr(value_ptr)
        print("!!! os_map2_set", map, key_ptr, value_ptr)

        # Preconditions
        mapp = self.state.metadata.get(Map, map)
        key = self.state.memory.load(key_ptr, mapp.key_size, endness=self.state.arch.memory_endness)
        value = self.state.memory.load(value_ptr, mapp.value_size, endness=self.state.arch.memory_endness)
        self.state.solver.add(claripy.Not(self.state.maps.get(mapp.items, key)[1]))
        print("!!! os_map2_set key and value", key, value)

        # Postconditions
        def case_true(state):
            self.state.maps.set(mapp.items, key, value)
            return claripy.BVV(1, bitsizes.bool)
        def case_false(state):
            return claripy.BVV(0, bitsizes.bool)
        return utils.fork_guarded(self, self.state, self.state.maps.length(mapp.items).ULT(mapp.capacity), case_true, case_false)


# void os_map2_remove(struct os_map2* map, void* key_ptr);
# requires mapp2(map, ?key_size, ?value_size, ?capacity, ?items) &*&
#          [?f]chars(key_ptr, key_size, ?key) &*&
#          ghostmap_get(items, key) != none;
# ensures [f]chars(key_ptr, key_size, key) &*&
#         mapp2(map, key_size, value_size, capacity, ghostmap_remove(items, key));
class OsMap2Remove(angr.SimProcedure):
    def run(self, map, key_ptr):
        # Casts
        map = cast.ptr(map)
        key_ptr = cast.ptr(key_ptr)
        print("!!! os_map2_remove", map, key_ptr)

        # Preconditions
        mapp = self.state.metadata.get(Map, map)
        key = self.state.memory.load(key_ptr, mapp.key_size, endness=self.state.arch.memory_endness)
        self.state.solver.add(self.state.maps.get(mapp.items, key)[1])
        print("!!! os_map2_remove key", key)

        # Postconditions
        self.state.maps.remove(mapp.items, key)

# No contract, not exposed publicly, only for symbex harnesses
class OsMap2Havoc(angr.SimProcedure):
    def run(self, map):
        map = cast.ptr(map)
        print("!!! os_map2_havoc", map)
        mapp = self.state.metadata.get(Map, map)
        self.state.maps.havoc(mapp.items, mapp.capacity, False)