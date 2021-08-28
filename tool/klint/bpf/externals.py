import angr
import claripy
from collections import namedtuple

from kalm import utils

BpfMapDef = namedtuple('BpfMapDef', ['type', 'key_size', 'value_size', 'max_entries', 'flags'])
BpfMap = namedtuple('BpfMap', ['map_def', 'values', 'items'])


# Not an external, called to mimic the kernel initializing a map
def map_init(state, addr, map_def):
    assert utils.definitely_true(state.solver, map_def.flags == 0) # no flags handled yet
    values = state.heap.allocate(map_def.max_entries, map_def.value_size * 8)
    items = state.maps.new(map_def.key_size * 8, state.sizes.ptr, "bpf_map")
    state.metadata.append(addr, BpfMap(map_def, values, items))

def align(n, val):
    if val % n == 0:
        return val
    return val + (n - (val % n))


# void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
# Returns NULL iff lookup failed, else a pointer to the actual value in the map (i.e., not a copy, can be mutated by users)
# Equivalent pseudo-VeriFast contract:
#  requires bpfmap(map, ?def, ?values, ?items) &*&
#           key != NULL &*&
#           [?f]chars(key, def.key_size, ?key_data);
#  ensures bpfmap(map, def, values, items) &*&
#          switch(ghostmap_get(items, key_data)) {
#              case none: result == NULL;
#              case some(i): result == values + i;
#          };
class bpf_map_lookup_elem(angr.SimProcedure):
    def run(self, map, key):
        # Casts
        map = self.state.casts.ptr(map)
        key = self.state.casts.ptr(key)

        # Preconditions
        bpfmap = self.state.metadata.get(BpfMap, map)
        assert utils.definitely_true(self.state.solver, key != 0)
        key_data = self.state.memory.load(key, bpfmap.map_def.key_size, endness=self.state.arch.memory_endness)

        # Postconditions
        def case_has(state, index):
            return bpfmap.values + index
        def case_not(state):
            return claripy.BVV(0, state.sizes.ptr)
        return utils.fork_guarded_has(self, self.state, bpfmap.items, key_data, case_has, case_not)

# long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)
# Copies both the key and the value into the map
# Equivalent pseudo-VeriFast contract:
#  requires bpfmap(map, ?def, ?values, ?items) &*&
#           key != NULL &*&
#           value != NULL &*&
#           [?fk]chars(key, def.key_size, ?key_data) &*&
#           [?fv]chars(value, def.value_size, ?value_data);
#  ensures flags == BPF_ANY ? (result == 0 &*& bpfmap(map, def, ghostmap_set??????????what to put here???)
#                           : ...we don't care...;
class bpf_map_update_elem(angr.SimProcedure):
    def run(self, map, key, value, flags):
        # Casts
        map = self.state.casts.ptr(map)
        key = self.state.casts.ptr(key)
        value = self.state.casts.ptr(value)
        flags = self.state.casts.uint64_t(flags)

        assert utils.definitely_true(self.state.solver, flags == 0) # BPF_ANY, we don't support the others for now

        # Preconditions
        bpfmap = self.state.metadata.get(BpfMap, map)
        assert utils.definitely_true(self.state.solver, (key != 0) & (value != 0))
        key_data = self.state.memory.load(key, bpfmap.map_def.key_size, endness=self.state.arch.memory_endness)
        value_data = self.state.memory.load(value, bpfmap.map_def.value_size, endness=self.state.arch.memory_endness)

        print("update", map, key, value, flags)
        print("map", self.state.metadata.get(BpfMap, map))
        raise "TODO"

# long bpf_map_delete_elem(struct bpf_map *map, const void *key)
class bpf_map_delete_elem(angr.SimProcedure):
    def run(self, map, key):
        print("delete", map, key)
        print("map", self.state.metadata.get(BpfMap, map))
        raise "TODO"

# void *__htab_map_lookup_elem(struct bpf_map *map, void *key)
# The specialized hash version of bpf_map_lookup_elem.
# It either returns NULL, or a pointer to a map element; the value is at an offset of aligned(8, 2*ptr + (2*ptr+u32) + u32) + aligned(8, the map key_size)
class __htab_map_lookup_elem(angr.SimProcedure):
    def run(self, map, key):
        bpfmap = self.state.metadata.get(BpfMap, map)
        result = self.inline_call(bpf_map_lookup_elem, map, key).ret_expr
        def case_null(state):
            return result
        def case_nonnull(state):
            # when the BPF code compensates, it'll add back the right value to return 'result'
            return result - align(8, 4 * (state.sizes.ptr // 8) + 2 * 4) - align(8, bpfmap.map_def.key_size)
        return utils.fork_guarded(self, self.state, result == 0, case_null, case_nonnull)

# int htab_map_update_elem(struct bpf_map *map, void *key, void *value, u64 map_flags)
class htab_map_update_elem(angr.SimProcedure):
    def run(self, map, key, value, flags):
        return self.inline_call(bpf_map_update_elem, map, key, value, flags).ret_expr[31:0] # for some bizarre reason this returns an int, not a long

# long bpf_redirect_map(struct bpf_map *map, u32 key, u64 flags)
# "XDP_REDIRECT on success, or the value of the two lower bits of the flags argument on error."
# The description makes it sound like the flags are not used for anything else, which a look at the source code confirms
# For now let's just make it always succeed
class bpf_redirect_map(angr.SimProcedure):
    def run(self, map, key, flags):
        return claripy.BVV(3, self.state.sizes.ptr) # XDP_TX

# long bpf_xdp_redirect_map(struct bpf_map *map, u32 key, u64 flags)
# In practice, an alias for bpf_redirect_map
class bpf_xdp_redirect_map(angr.SimProcedure):
    def run(self, map, key, flags):
        return self.inline_call(bpf_redirect_map, map, key, flags).ret_expr

# u64 bpf_ktime_get_ns(void)
class bpf_ktime_get_ns(angr.SimProcedure):
    def run(self):
        print("ktime")
        raise "TODO"
