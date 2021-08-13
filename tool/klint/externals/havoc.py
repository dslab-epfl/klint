# This file is a kind of hack to support Katran, which assumes maps are set by userspace;
# without havocing, there's only 1 path that is an early failure
# The alternative would be to treat all bpf_map_* calls as unconstrained externals, but that feels even more hacky
# (it'd work for Katran, but in general one still wants set-then-get to result in something coherent...)

import angr
import claripy
import math

from klint import ghostmaps
from klint import heap
from klint.externals.structs.map import Map
from klint.externals.structs.index_pool import Pool

# void klint_havoc_array(void* values);
class klint_havoc_array(angr.SimProcedure):
    def run(self, values):
        values = self.state.casts.ptr(values)

        # Reset the invariant to the original array one, which states nothing about values
        length = self.state.maps.length(values)
        self.state.maps.UNSAFE_havoc(values,
            length,
            [lambda i: (i.key < length) == i.present]
        )

# void klint_havoc_hashmap(struct map* map, struct index_pool* index_pool, void* keys, void* values);
class klint_havoc_hashmap(angr.SimProcedure):
    def run(self, map, index_pool, keys, values):
        map = self.state.casts.ptr(map)
        index_pool = self.state.casts.ptr(index_pool)
        keys = self.state.casts.ptr(keys)
        values = self.state.casts.ptr(values)

        # Get the actual ghost map objects
        map_values = self.state.metadata.get(Map, map).values
        map_addrs = self.state.metadata.get(Map, map).addrs
        pool_items = self.state.metadata.get(Pool, index_pool).items
        keys_fracs = self.state.metadata.get(heap.HeapPlugin.Metadata, keys).fractions

        # Create a new havoced length
        map_capacity = self.state.maps.length(keys)
        havoced_length = claripy.BVS("havoced_length", self.state.sizes.size_t)
        self.state.solver.add(havoced_length.ULE(map_capacity))

        # Havoc the keys and values
        self.state.maps.UNSAFE_havoc(keys, map_capacity, [lambda i: (i.key < map_capacity) == i.present])
        self.state.maps.UNSAFE_havoc(values, map_capacity, [lambda i: (i.key < map_capacity) == i.present])

        # Havoc the fractions to be either 75 or 100
        self.state.maps.UNSAFE_havoc(keys_fracs, map_capacity, [
            (lambda i: (i.key < map_capacity) == i.present),
            (lambda i: (i.value == 75) | (i.value == 100))
        ])

        # Set the right invariant over the map/pool, which states nothing about actual map keys/values
        # but still ensures they are consistent.
        # In comments are the invariants inferred for the firewall
        keysize = self.state.metadata.get(Map, map).key_size
        log2_keysize = int(math.log2(self.state.solver.eval_one(keysize)))

        def implies(a, b): return ~a | b

        self.state.maps.UNSAFE_havoc(keys, havoced_length, [
        #Inferred: when KEYS contains (K,V), if MapGet(K_FRACS, K, None) == 75 then M_VALUES contains V
        #          in addition, the value is K
            (lambda i: implies(i.present, implies(ghostmaps.MapGet(keys_fracs, i.key, 8) == 75, ghostmaps.MapHas(map_values, i.value, value=i.key)))),
        #Inferred: when KEYS contains (K,V), if MapGet(K_FRACS, K, None) == 75 then M_ADDRS contains V
        #          in addition, the value is (K << log2(KEY_SIZE)) + KEYS
            (lambda i: implies(i.present, implies(ghostmaps.MapGet(keys_fracs, i.key, 8) == 75, ghostmaps.MapHas(map_addrs, i.value, value=((i.key << log2_keysize) + keys))))),
        #Inferred: when KEYS contains (K,V), if MapGet(K_FRACS, K, None) == 75 then POOL contains K
            (lambda i: implies(i.present, implies(ghostmaps.MapGet(keys_fracs, i.key, 8) == 75, ghostmaps.MapHas(pool_items, i.key))))
        ])

        self.state.maps.UNSAFE_havoc(map_values, havoced_length, [
        #Inferred: when M_VALUES contains (K,V), then KEYS contains V
        #          in addition, the value is K
            (lambda i: implies(i.present, ghostmaps.MapHas(keys, i.value, value=i.key))),
        #Inferred: when M_VALUES contains (K,V), then K_FRACS contains V
        #          in addition, the value is 75
            (lambda i: implies(i.present, ghostmaps.MapHas(keys_fracs, i.value, value=claripy.BVV(75, 8)))),
        #Inferred: when M_VALUES contains (K,V), then M_ADDRS contains K
        #          in addition, the value is (V << log2(KEY_SIZE)) + KEYS
            (lambda i: implies(i.present, ghostmaps.MapHas(map_addrs, i.key, value=((i.value << log2_keysize) + keys)))),
        #Inferred: when M_VALUES contains (K,V), then POOL contains V
            (lambda i: implies(i.present, ghostmaps.MapHas(pool_items, i.value)))
        ])

        self.state.maps.UNSAFE_havoc(map_addrs, havoced_length, [
        #Inferred: when M_ADDRS contains (K,V), then M_VALUES contains K
            lambda i: implies(i.present, ghostmaps.MapHas(map_values, i.key))
        ])

        self.state.maps.UNSAFE_havoc(pool_items, havoced_length, [
        #Inferred: when POOL contains (K,V), then KEYS contains K
            (lambda i: implies(i.present, ghostmaps.MapHas(keys, i.key))),
        #Inferred: when POOL contains (K,V), then K_FRACS contains K
        #          in addition, the value is 75
            (lambda i: implies(i.present, ghostmaps.MapHas(keys_fracs, i.key, claripy.BVV(75, 8)))),
        # These ones is inferred within the map
            (lambda i: implies(i.present, i.value != claripy.BVV(-1, self.state.sizes.uint64_t))),
            (lambda i: implies(i.present, i.key.ULT(map_capacity)))
        ])
