import angr
from angr.sim_type import *
import claripy
from collections import namedtuple

from kalm import utils


Lpm = namedtuple("lpmp", ["table", "key_size", "value_size", "capacity"])

# struct lpm* lpm_alloc(size_t key_size, size_t value_size, size_t capacity);
class LpmAlloc(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypeLength(False), SimTypeLength(False), SimTypeLength(False)], SimTypePointer(SimTypeBottom(label="void")), arg_names=["key_size", "value_size", "capacity"])

    def run(self, key_size, value_size, capacity):
        # Preconditions
        if key_size.symbolic:
            raise Exception("Key size cannot be symbolic")
        if value_size.symbolic:
            raise Exception("Value size cannot be symbolic")
        # NOTE: we will likely want to limit key_size, value_size, and capacity, since an implementation cannot support arbitrarily long ones
        # (e.g. if entries are 2 bytes then one cannot have 2^64 entries with 64-bit pointers)
        # but for now it's fine

        # Postconditions
        result = claripy.BVS("lpm", self.state.sizes.ptr)
        table = self.state.maps.new(key_size * 8 + self.state.sizes.size_t, value_size * 8, "lpm_table")
        self.state.metadata.append(result, Lpm(table, key_size, value_size, capacity))
        print(f"!!! lpm_alloc -> {result}")
        return result


# bool lpm_set(struct lpm* lpm, void* key, size_t width, void* value);
class LpmSet(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction(
            [SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void")), SimTypeLength(False), SimTypePointer(SimTypeBottom(label="void"))],
            SimTypeBool(),
            arg_names=["lpm", "key", "width", "value"]
        )

    def run(self, lpm, key_ptr, width, value_ptr):
        # Preconditions
        lpmp = self.state.metadata.get(Lpm, lpm)
        key = self.state.memory.load(key_ptr, lpmp.key_size, endness=self.state.arch.memory_endness)
        value = self.state.memory.load(value_ptr, lpmp.value_size, endness=self.state.arch.memory_endness)

        assert utils.definitely_true(self.state.solver,
            width <= lpmp.key_size * 8
        )

        print(f"!!! lpm_set {key}/{width} {value}")

        # Postconditions
        def case_true(state):
            self.state.maps.set(lpmp.table, key.concat(width), value)
            return claripy.BVV(1, state.sizes.bool)
        def case_false(state):
            return claripy.BVV(0, state.sizes.bool)
        return utils.fork_guarded(self, self.state, self.state.maps.get(lpmp.table, key.concat(width))[1] | (self.state.maps.length(lpmp.table) < lpmp.capacity), case_true, case_false)

# bool lpm_search(struct lpm* lpm, void* key, void* out_value);
class LpmSearch(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction(
            [SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void"))],
            SimTypeBool(),
            arg_names=["lpm", "key", "out_value"]
        )

    def run(self, lpm, key_ptr, out_value):
        # Preconditions
        lpmp = self.state.metadata.get(Lpm, lpm)
        key = self.state.memory.load(key_ptr, lpmp.key_size, endness=self.state.arch.memory_endness)
        self.state.memory.load(out_value, lpmp.value_size)

        print(f"!!! lpm_search {key}")

        def matches(item):
            # What we want is "(item.k >> shift) == (key >> shift)" where shift is key_size-item.width
            # However, we have to jump through hoops to make all of the BV sizes match, and we need LShR for our semantics as >> is signed
            # Ideally we'd have a DSL that would take care of this stuff, like we have for specs
            item_k = item[:self.state.sizes.size_t]
            item_width = item[self.state.sizes.size_t-1:]
            zext_key = key
            zext_key_size = lpmp.key_size
            if item_k.length < item_width.length:
                item_k = item_k.zero_extend(item_width.length - item_k.length)
                zext_key = zext_key.zero_extend(item_width.length - zext_key.length)
            if item_width.length < item_k.length:
                item_width = item_width.zero_extend(item_k.length - item_width.length)
                zext_key_size = zext_key_size.zero_extend(item_k.length - zext_key_size.length)
            # don't forget key_size is in bytes!
            shift = zext_key_size * 8 - item_width
            return item_k.LShR(shift) == zext_key.LShR(shift)

        def case_false(state):
            print("!!! lpm_search: not found")
            return claripy.BVV(0, state.sizes.bool)
        def case_true(state):
            print("!!! lpm_search: found")
            width = claripy.BVS("width", state.sizes.size_t)
            full_key = key.concat(width)
            (value, has) = state.maps.get(lpmp.table, full_key)
            state.solver.add(
                has,
                matches(full_key),
                state.maps.forall(lpmp.table, lambda k, v: ~matches(k) | (k[state.sizes.size_t-1:] < width) | (v == value))
            )
            state.memory.store(out_value, value, endness=state.arch.memory_endness)
            return claripy.BVV(1, state.sizes.bool)
        return utils.fork_guarded(self, self.state, self.state.maps.forall(lpmp.table, lambda k, v: ~matches(k)), case_false, case_true)

# void lpm_remove(struct lpm* lpm, void* key, size_t width);
class LpmRemove(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBottom(label="void")), SimTypeLength(False)], None, arg_names=["lpm", "key", "key_mask"])

    def run(self, lpm, key_ptr, width):
        lpmp = self.state.metadata.get(Lpm, lpm)
        key = self.state.memory.load(key_ptr, lpmp.key_size, endness=self.state.arch.memory_endness)
        print("!!! lpm_remove", lpm, key_ptr, width)
        self.state.maps.remove(lpmp.table, key.concat(width))
