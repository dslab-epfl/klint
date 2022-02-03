import angr
from angr.sim_type import *
import claripy
from collections import namedtuple

from kalm import utils
from klint.bpf import detection
from klint.bpf import packet
from klint.ghostmaps import MapHas

BpfMapDef = namedtuple('BpfMapDef', ['type', 'key_size', 'value_size', 'max_entries', 'flags'])
BpfMap = namedtuple('BpfMap', ['map_def', 'values', 'items'])

def align(val, n):
    if not isinstance(val, int):
        if val.symbolic: raise Exception("nope")
        val = val.args[0]
    if val % n == 0:
        return val
    return val + (n - (val % n))

# Not an external, called to mimic the kernel initializing a map
# Returns None or a map containing existing invariant inference results, to make havocing efficient
def map_init(state, addr, map_def, havoc):
    # we use ephemeral maps because the kernel is just fine with overwriting content if others could still hold pointers to it
    # (e.g., write to an element if a get returned a pointer to it)

    assert utils.definitely_true(state.solver, map_def.flags == 0) # no flags handled yet

    if map_def.type == 1:
        # Hash map
        # NOTE: There's also type 9 LRU_HASH, but it needs to never fail on inserts due to LRU,
        #       and also there's some more complex inlining going on with a write to the map element's "lru node"... so it's not that simple
        values = state.heap.allocate(map_def.max_entries, map_def.value_size, ephemeral=True, name="bpf_values")
        length = None
        invariants = None
        if havoc:
            length = claripy.BVS("havoced_length", state.sizes.ptr)
            state.solver.add(length.ULE(map_def.max_entries))
            invariants = [lambda i: ~i.present | i.value.ULT(map_def.max_entries)]
        items = state.maps.new(map_def.key_size * 8, state.sizes.ptr, "bpf_map", _length=length, _invariants=invariants)
        state.metadata.append(addr, BpfMap(map_def, values, items))
        # This holds by construction, let's not possibly waste an inference iteration discovering it
        return {items.cache_key: [lambda st: st.maps.length(items) <= st.maps.length(values)]}
    elif map_def.type == 2:
        # Array, the code won't use functions to access it, just direct memory accesses, though there's an offset to the data

        # See bpf/packet.py for a detailed explanation
        # Figure this out by looking at a BPF dump, it's an addition immediately after loading the array address
        linux_ver = detection.get_linux_version()
        if linux_ver.startswith('5.4.0-81') and detection.is_64bit():
            offset = 0xD0
        elif linux_ver.startswith('5.10') and detection.is_64bit():
            offset = 0x110
        else:
            raise("Sorry, you need to do some work here: " + __file__)

        # The kernel rounds up the value size
        value_size = align(map_def.value_size, 8)
        default = None
        if not havoc:
            default = claripy.BVV(0, value_size * 8)
        state.heap.allocate(map_def.max_entries, value_size, ephemeral=True, addr=addr+offset, default=default, name="bpf_array")
    elif map_def.type == 6:
        # Per-cpu array, like an array but accessed with explicit function calls
        # The kernel rounds up the value size
        value_size = align(map_def.value_size, 8)
        default = None
        if not havoc:
            default = claripy.BVV(0, value_size * 8)
        map_def = BpfMapDef(map_def.type, map_def.key_size, value_size, map_def.max_entries, map_def.flags)
        values = state.heap.allocate(map_def.max_entries, map_def.value_size, ephemeral=True, default=default, name="bpf_percpuarray")
        state.metadata.append(addr, BpfMap(map_def, values, None))
    elif map_def.type == 14 or map_def.type == 16:
        # Dev or CPU map, only for redirect calls, we don't fully model those yet
        return
    else:
        raise Exception("Unsupported map type: " + str(map_def.type))


# void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
class bpf_map_lookup_elem(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void"))], SimTypePointer(SimTypeBottom(label="void")), arg_names=["map", "key"])

    def run(self, map, key):
        bpfmap = self.state.metadata.get(BpfMap, map)
        key_data = self.state.memory.load(key, bpfmap.map_def.key_size, endness=self.state.arch.memory_endness)

        if bpfmap.items is None:
            # Per-CPU array
            key_data = key_data.zero_extend(self.state.sizes.ptr - key_data.size())
            def case_true(state):
                return bpfmap.values + key_data * bpfmap.map_def.value_size
            def case_false(state):
                return claripy.BVV(0, state.sizes.ptr)
            return utils.fork_guarded(self, self.state, key_data.ULT(bpfmap.map_def.max_entries), case_true, case_false)

        print("lookup", map, key)
        print("map", self.state.metadata.get(BpfMap, map))
        raise "TODO"

# long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)
class bpf_map_update_elem(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void")), SimTypeNum(64, False)], SimTypeLong(True), arg_names=["map", "key", "value", "flags"])

    def run(self, map, key, value, flags):
        assert utils.definitely_true(self.state.solver, flags == 0)

        bpfmap = self.state.metadata.get(BpfMap, map)
        key_data = self.state.memory.load(key, bpfmap.map_def.key_size, endness=self.state.arch.memory_endness)
        value_data = self.state.memory.load(value, bpfmap.map_def.value_size, endness=self.state.arch.memory_endness)

        if bpfmap.items is None:
            # Per-CPU array
            key_data = key_data.zero_extend(self.state.sizes.ptr - key_data.size())
            def case_true(state):
                self.state.memory.store(bpfmap.values + key_data * bpfmap.map_def.value_size, value_data, endness=self.state.arch.memory_endness)
                return claripy.BVV(0, 64)
            def case_false(state):
                return claripy.BVV(-1, 64)
            return utils.fork_guarded(self, self.state, key_data.ULT(bpfmap.map_def.max_entries), case_true, case_false)

        print("update", map, key, value, flags)
        print("map", self.state.metadata.get(BpfMap, map))
        raise "TODO"

# long bpf_map_delete_elem(struct bpf_map *map, const void *key)
class bpf_map_delete_elem(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void"))], SimTypeLong(True), arg_names=["map", "key"])

    def run(self, map, key):
        print("delete", map, key)
        print("map", self.state.metadata.get(BpfMap, map))
        raise "TODO"

class percpu_array_map_lookup_elem(bpf_map_lookup_elem):
    pass

# void *__htab_map_lookup_elem(struct bpf_map *map, void *key)
# The specialized hash version of bpf_map_lookup_elem.
# Returns NULL iff lookup failed, else a pointer to the actual value in the map (i.e., not a copy, can be mutated by users)
# Equivalent pseudo-VeriFast contract:
#  requires bpfmap(map, ?def, ?values, ?items) &*&
#           [?f]chars(key, def.key_size, ?key_data);
#  ensures bpfmap(map, def, values, items) &*&
#          switch(ghostmap_get(items, key_data)) {
#              case none: result == NULL;
#              case some(i): result == values + i * def.value_size;
#          };
# HOWEVER: if the result is non-NULL, it's negatively shifted by some amount
#          because what it really returns is a pointer to the hash table entry, and the BPF code compensates to find the pointer to the value
class __htab_map_lookup_elem(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void"))], SimTypePointer(SimTypeBottom(label="void")), arg_names=["map", "key"])

    def run(self, map, key):
        print("!!! __htab_map_lookup_elem", map, key)

        # Preconditions
        bpfmap = self.state.metadata.get(BpfMap, map)
        key_data = self.state.memory.load(key, bpfmap.map_def.key_size, endness=self.state.arch.memory_endness)

        # Postconditions
        def case_has(state, index):
            print("!!! __htab_map_lookup has", index)
            result = bpfmap.values + index * bpfmap.map_def.value_size
            linux_ver = detection.get_linux_version()
            # See bpf/packet.py for a detailed explanation
            # Figure this out by looking at a BPF dump that includes a call to __htab_map_lookup_elem :-/
            # Alternatively, try with the existing offset and see if it works or if it obviously needs a correction (e.g. the code is trying to access an item 1 off the target)
            if (linux_ver.startswith('5.4.0-81') or linux_ver.startswith('5.10')) and detection.is_64bit():
                offset = 48 + align(bpfmap.map_def.key_size, 8)
            else:
                raise("Sorry, you need to do some work here: " + __file__)
            return result - offset
        def case_not(state):
            print("!!! __htab_map_lookup has not")
            return claripy.BVV(0, state.sizes.ptr)
        return utils.fork_guarded_has(self, self.state, bpfmap.items, key_data, case_has, case_not)

# int htab_map_update_elem(struct bpf_map *map, void *key, void *value, u64 map_flags)
# Copies both the key and the value into the map
# Equivalent pseudo-VeriFast contract (very "pseudo" here):
#  requires bpfmap(map, ?def, ?values, ?items) &*&
#           [?fk]chars(key, def.key_size, ?key_data) &*&
#           [?fv]chars(value, def.value_size, ?value_data) &*&
#           flags == BPF_ANY; // TODO remove this one at some point
#  ensures [fk]chars(key, def.key_size, key_data) &*&
#          [fv]chars(value, def.value_size, value_data) &*&
#          switch(ghostmap_get(items, key_data)) {
#              case some: result == 0 &*& bpfmap(map, def, values, items) &*& [0]chars(values + i * def.value_size, def.value_size, value_data); // unsound overwite by design!
#              case none: length(items) == def.max_entries ? result == -1 &*& bpfmap(map, def, values, items)
#                                                          : result == 0 &*& bpfmap(map, def, values, ghostmap_set(items, key_data, ?i)) &*&
#                                                            0 <= i &*& i < bpfmap.def.max_entries &*&
#                                                            [100]chars(values + i * def.value_size, def.value_size, value_data);
#          };
class htab_map_update_elem(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void")), SimTypeNum(64, False)], SimTypeInt(True), arg_names=["map", "key", "value", "map_flags"])

    def run(self, map, key, value, flags):
        # Preconditions
        bpfmap = self.state.metadata.get(BpfMap, map)
        key_data = self.state.memory.load(key, bpfmap.map_def.key_size, endness=self.state.arch.memory_endness)
        value_data = self.state.memory.load(value, bpfmap.map_def.value_size, endness=self.state.arch.memory_endness)
        assert utils.definitely_true(self.state.solver, flags == 0)

        def case_has(state, i):
            value_ptr = bpfmap.values + i * bpfmap.map_def.value_size
            state.memory.store(value_ptr, value_data, endness=state.arch.memory_endness)
            return claripy.BVV(0, 32)
        def case_not(state):
            def case_true(state):
                return claripy.BVV(-1, 32)
            def case_false(state):
                i = claripy.BVS("i", state.sizes.ptr)
                state.solver.add(i.UGE(0) & i.ULT(bpfmap.map_def.max_entries))
                value_ptr = bpfmap.values + i * bpfmap.map_def.value_size
                state.memory.store(value_ptr, value_data, endness=state.arch.memory_endness)
                state.maps.set(bpfmap.items, key_data, i)
                return claripy.BVV(0, 32)
            return utils.fork_guarded(self, state, state.maps.length(bpfmap.items) == bpfmap.map_def.max_entries, case_true, case_false)
        return utils.fork_guarded_has(self, self.state, bpfmap.items, key_data, case_has, case_not)

class htab_lru_map_update_elem(htab_map_update_elem):
    pass

# int htab_map_delete_elem(struct bpf_map *map, void *key)
# pseudo-VeriFast contract:
#  requires bpfmap(map, ?def, ?values, ?items) &*&
#           [?f]chars(key, def.key_size, ?key_data);
#  ensures [f]chars(key, def.key_size, key_data) &*&
#          switch(ghostmap_get(items, key_data)) {
#              case some(i): result == 0 &*& bpfmap(map, def, values, ghostmap_remove(items, key_data));
#              case none: result == -1 &*& bpfmap(map, def, values, items);
#          };
class htab_map_delete_elem(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void"))], SimTypeInt(True), arg_names=["map", "key"])

    def run(self, map, key):
        # Preconditions
        bpfmap = self.state.metadata.get(BpfMap, map)
        key_data = self.state.memory.load(key, bpfmap.map_def.key_size, endness=self.state.arch.memory_endness)

        # Postconditions
        def case_has(state, i):
            state.maps.remove(bpfmap.items, i)
            return claripy.BVV(0, 32)
        def case_not(state):
            return claripy.BVV(-1, 32)
        return utils.fork_guarded_has(self, self.state, bpfmap.items, key_data, case_has, case_not)

# long bpf_redirect_map(struct bpf_map *map, u32 key, u64 flags)
# "XDP_REDIRECT on success, or the value of the two lower bits of the flags argument on error."
# The description makes it sound like the flags are not used for anything else, which a look at the source code confirms
# For now let's just make it always succeed
class bpf_redirect_map(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypeNum(32, False), SimTypeNum(64, False)], SimTypeLong(True), arg_names=["map", "key", "flags"])

    def run(self, map, key, flags):
        return claripy.BVV(3, self.state.sizes.ptr) # XDP_TX

# long bpf_xdp_redirect_map(struct bpf_map *map, u32 key, u64 flags)
# In practice, an alias for bpf_redirect_map
class bpf_xdp_redirect_map(bpf_redirect_map):
    pass

# u64 bpf_ktime_get_ns(void)
class bpf_ktime_get_ns(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([], SimTypeNum(64, False))

    def run(self):
        return claripy.BVS("bpf_ktime_ns", 64)

# s64 bpf_csum_diff(__be32 *from, u32 from_size, __be32 *to, u32 to_size, __wsum seed)
class bpf_csum_diff(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction(
            [SimTypePointer(SimTypeNum(32, False)), SimTypeNum(32, False), SimTypePointer(SimTypeNum(32, False)), SimTypeNum(32, False), SimTypeNum(32, False)],
            SimTypeNum(64, True),
            arg_names=["from", "from_size", "to", "to_size", "seed"])

    def run(self, fromm, from_size, to, to_size, seed):
        # TODO we don't really handle checksums for now, anyway this is just engineering
        return claripy.BVV(0, 64)

# long bpf_xdp_adjust_head(struct xdp_buff *xdp_md, int delta)
class bpf_xdp_adjust_head(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypeInt(True)], SimTypeLong(True), arg_names=["xdp_md", "delta"])

    def run(self, xdp_md, delta):
        delta = delta.sign_extend(self.state.sizes.ptr - 32) # need to extend it so we can use it with pointer-sized stuff...

        length = packet.get_length(self.state, xdp_md)
        def case_true(state):
            packet.adjust_data_head(state, xdp_md, delta)
            return claripy.BVV(0, 64)
        def case_false(state):
            return claripy.BVV(-1, 64)
        # TODO: should we randomly fail to mimic an allocation failure? can this ever happen in the kernel?
        return utils.fork_guarded(self, self.state, length.SGE(delta) & (length - delta).ULE(packet.PACKET_MTU), case_true, case_false)

rand_value = claripy.BVS("bpf_user_rnd_u32_result", 32)
# u32 bpf_user_rnd_u32(void)
class bpf_user_rnd_u32(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([], SimTypeNum(32, False))

    def run(self):
        # TODO ensure this is sound by checking it's called at most once (otherwise we just need a global to hold all random vals and keep track of idx per state...)
        return rand_value
