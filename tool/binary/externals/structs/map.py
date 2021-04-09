import angr
import claripy
from collections import namedtuple

import binary.cast as cast
import binary.utils as utils


# predicate mapp(struct map* map, size_t key_size, size_t capacity, list<pair<list<char>, size_t> > values, list<pair<list<char>, void*> > addrs);
Map = namedtuple('mapp', ['key_size', 'capacity', 'values', 'addrs'])

# struct map* map_alloc(size_t key_size, size_t capacity);
# requires capacity * 64 <= SIZE_MAX;
# ensures mapp(result, key_size, capacity, nil, nil);
class map_alloc(angr.SimProcedure):
    def run(self, key_size, capacity):
        # Casts
        key_size = cast.size_t(key_size)
        capacity = cast.size_t(capacity)

        # Symbolism assumptions
        if key_size.symbolic:
            raise Exception("key_size cannot be symbolic")

        # Preconditions
        self.state.solver.add((capacity * 64).ULE(2 ** self.state.sizes.size_t - 1))

        # Postconditions
        result = claripy.BVS("map", self.state.sizes.ptr)
        values = self.state.maps.new(key_size * 8, self.state.sizes.ptr, "map_values") # key_size is in bytes
        addrs = self.state.maps.new(key_size * 8, self.state.sizes.ptr, "map_addrs") # key_size is in bytes
        self.state.metadata.append(result, Map(key_size, capacity, values, addrs))
        print("!!! map_alloc", key_size, capacity, "->", result)
        return result

# bool map_get(struct map* map, void* key_ptr, size_t* out_value);
# requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
#          [?frac]chars(key_ptr, key_size, ?key) &*&
#          *out_value |-> _;
# ensures mapp(map, key_size, capacity, values, addrs) &*&
#         [frac]chars(key_ptr, key_size, key) &*&
#         switch(ghostmap_get(values, key)) {
#           case none: return result == false &*& *out_value |-> _;
#           case some(v): return result == true &*& *out_value |-> v;
#         };
class map_get(angr.SimProcedure):
    def run(self, map, key_ptr, out_value):
        # Casts
        map = cast.ptr(map)
        key_ptr = cast.ptr(key_ptr)
        out_value = cast.ptr(out_value)
        print("!!! map_get", map, key_ptr, out_value)

        # Preconditions
        mapp = self.state.metadata.get(Map, map)
        key = self.state.memory.load(key_ptr, mapp.key_size, endness=self.state.arch.memory_endness)
        self.state.memory.load(out_value, self.state.sizes.ptr // 8)
        print("!!! map_get key", key)

        # Postconditions
        def case_has(state, v):
            print("!!! map_get has", v)
            self.state.memory.store(out_value, v, endness=self.state.arch.memory_endness)
            return claripy.BVV(1, self.state.sizes.bool)
        def case_not(state):
            print("!!! map_get not")
            return claripy.BVV(0, self.state.sizes.bool)
        return utils.fork_guarded_has(self, self.state, mapp.values, key, case_has, case_not)

# void map_set(struct map* map, void* key_ptr, size_t value);
# requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
#          [0.25]chars(key_ptr, key_size, ?key) &*&
#          length(values) < capacity &*&
#          ghostmap_get(values, key) == none &*&
#          ghostmap_get(addrs, key) == none;
# ensures mapp(map, key_size, capacity, ghostmap_set(values, key, value), ghostmap_set(addrs, key, key_ptr));
class map_set(angr.SimProcedure):
    def run(self, map, key_ptr, value):
        # Casts
        map = cast.ptr(map)
        key_ptr = cast.ptr(key_ptr)
        value = cast.ptr(value)
        print("!!! map_set", map, key_ptr, value)

        # Preconditions
        mapp = self.state.metadata.get(Map, map)
        key = self.state.memory.load(key_ptr, mapp.key_size, endness=self.state.arch.memory_endness)
        self.state.memory.take(25, key_ptr)
        self.state.solver.add(
            self.state.maps.length(mapp.values) < mapp.capacity,
            claripy.Not(self.state.maps.get(mapp.values, key)[1]),
            claripy.Not(self.state.maps.get(mapp.addrs, key)[1])
        )
        print("!!! map_set key", key)

        # Postconditions
        self.state.maps.set(mapp.values, key, value)
        self.state.maps.set(mapp.addrs, key, key_ptr)

# void map_remove(struct map* map, void* key_ptr);
# requires mapp(map, ?key_size, ?capacity, ?values, ?addrs) &*&
#          [?frac]chars(key_ptr, key_size, ?key) &*&
#          frac != 0.0 &*&
#          ghostmap_get(values, key) != none &*&
#          ghostmap_get(addrs, key) == some(key_ptr);
# ensures mapp(map, key_size, capacity, ghostmap_remove(values, key), ghostmap_remove(addrs, key)) &*&
#         [frac + 0.25]chars(key_ptr, key_size, key);
class map_remove(angr.SimProcedure):
    def run(self, map, key_ptr):
        # Casts
        map = cast.ptr(map)
        key_ptr = cast.ptr(key_ptr)
        print("!!! map_remove", map, key_ptr)

        # Preconditions
        mapp = self.state.metadata.get(Map, map)
        key = self.state.memory.load(key_ptr, mapp.key_size, endness=self.state.arch.memory_endness)
        frac = self.state.memory.take(None, key_ptr)
        self.state.solver.add(
            self.state.maps.get(mapp.values, key)[1],
            self.state.maps.get(mapp.addrs, key)[1],
            self.state.maps.get(mapp.addrs, key)[0] == key_ptr
        )
        print("!!! map_remove key", key)

        # Postconditions
        self.state.maps.remove(mapp.values, key)
        self.state.maps.remove(mapp.addrs, key)
        self.state.memory.give(frac + 25, key_ptr)
