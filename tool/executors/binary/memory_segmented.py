import angr
import archinfo
from angr.state_plugins.plugin import SimStatePlugin
from angr.storage.memory import SimMemory
import executors.binary.bitsizes as bitsizes
import executors.binary.utils as utils


# Supports loads and stores, as well as "allocate(count, size, ?default) -> addr_symbol" and "base_index_offset(addr_symbol) -> (base_symbol, index_symbol, offset)"; all methods take sizes in bytes but offset is in bits
# Does not support any other endness than BE
class SegmentedMemory(SimMemory):
    def __init__(self, memory_id='', segments=None):
        SimMemory.__init__(self, endness=archinfo.Endness.BE, abstract_backer=None, stack_region_map=None, generic_region_map=None)
        self.id = memory_id # magic! needs to be set for SimMemory to work
        self.segments = [] if segments is None else segments


    def set_state(self, state):
        SimMemory.set_state(self, state)


    @SimStatePlugin.memo
    def copy(self, memo):
        return SegmentedMemory(memory_id=self.id, segments=self.segments.copy())


    def merge(self, others, merge_conditions, common_ancestor=None):
        if any(o.id != self.id for o in others) or any(o.endness != self.endness for o in others):
            raise "Merging SegmentedMemory instances with different IDs or endnesses is not supported"
        new_segments = set(self.segments)
        for o in others:
            new_segments.update(o.segments)
        self.segments = list(new_segments)
        return True


    def _to_bv64(self, val): # just a helper function, not some angr internal or anything
        if isinstance(val, int):
            return self.state.solver.BVV(val, 64)
        return val.zero_extend(64 - val.length)


    def _store(self, request): # request is MemoryStoreRequest; has addr, data=None, size=None, condition=None, endness + "completed" must be set to True and "stored_values" must be set to a singleton list of the written data
        if request.data is None or request.size is None or request.condition is not None:
            raise "Sorry, can't handle that yet"
        if request.size.symbolic:
            raise "Can't handle symbolic sizes"
        if request.endness is not None and request.endness != self.endness:
            raise "SegmentedMemory supports only BE endness"

        data = request.data
        size = self.state.solver.eval_one(request.size, cast_to=int) * 8 # we get the size in bytes

        (base, index, offset) = self.base_index_offset(request.addr)
        element_size = self.state.maps.value_size(base)

        if offset == 0 and size == element_size:
            value = data
        else:
            full = self.state.maps.get(base, index)
            if offset + size < full.length:
                value = full[(full.length-1):(offset+size)].concat(data)
            else:
                value = data
            if offset > 0:
                value = value.concat(full[offset-1:0])

        self.state.maps.set(base, index, value)
        request.completed = True
        request.stored_values = [data]


    def _load(self, addr, size, condition=None, fallback=None, inspect=True, events=True, ret_on_segv=False):
        size = self._to_bv64(size) * 8 # we get the size in bytes

        if condition is not None or fallback is not None or ret_on_segv:
            raise "Sorry, can't handle that yet"
        if size.symbolic:
            raise "Can't handle symbolic sizes"

        size = self.state.solver.eval_one(size, cast_to=int)
        (base, index, offset) = self.base_index_offset(addr)

        value = self.state.maps.get(base, index)
        if offset == 0 and size == self.state.maps.value_size(base):
            return [addr], value, []
        else:
            return [addr], value[(offset+size-1):offset], []


    def _find(self, start, what, max_search=None, max_symbolic_bytes=None, default=None, step=1, disable_actions=False, inspect=True, chunk_size=None):
        raise NotImplementedError() # do we need this?


    def _copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None, inspect=True, disable_actions=False):
        raise NotImplementedError() # do we need this?


    def allocate(self, count, size, default=None, name=None):
        count = self._to_bv64(count)
        size = self._to_bv64(size) * 8 # we get a size in bytes

        max_size = self.state.solver.max(size)
        if max_size // 8 > 4096:
            raise ("That's a huge block you want to allocate... let's just not: " + str(max_size))

        name = (name or "segmented_memory") + "_addr"
        addr = self.state.maps.allocate(bitsizes.PTR, max_size, name=name, array_length=count, default_value=default)
        # neither null nor so high it overflows (note the -1 becaus 1-past-the-array is legal C)
        self.state.add_constraints(addr != 0, addr.ULE(self.state.solver.BVV(2**bitsizes.PTR-1, bitsizes.PTR) - max_size - 1))
        self.segments.append((addr, count, size))
        return addr

    def _count_size(self, addr):
        # Optimization: Try structurally matching first before invoking the solver
        result = next(((count, size) for (cand_addr, count, size) in self.segments if addr.structurally_match(cand_addr)), None)
        if result is None:
            results = [(count, size) for (cand_addr, count, size) in self.segments if utils.definitely_true(self.state.solver, addr == cand_addr)]
            if len(results) == 0:
                raise ("No segment with base: " + str(addr))
            if len(results) > 1:
                raise ("Multiple possible segments with base: " + str(addr))
            result = results[0]
        # more convenient
        return self._to_bv64(result[0]), self._to_bv64(result[1])

    # Guarantees that:
    # - Result is of the form (base, index, offset)
    # - 'base': BV, is a symbolic pointer, but "concrete" here in that it must be exactly 1 pointer
    # - 'index': BV, is a symbolic index, could be anything
    # - 'offset': int, is an offset in bits, concrete
    def base_index_offset(self, addr):
        def as_simple(val):
            if val.op == "BVS": return val
            if val.op == '__add__' and len(val.args) == 1: return as_simple(val.args[0])
            if val.op == 'Extract': return val
            return None

        simple_addr = as_simple(addr)
        if simple_addr is not None:
            return (simple_addr, self.state.solver.BVV(0, 64), 0) # Directly addressing a base, i.e., base[0]

        if addr.op == '__add__':
            base = [a for a in map(as_simple, addr.args) if a is not None]
            if len(base) == 1:
                base = base[0]
            else:
                raise "!= 1 candidate for base???"
            added = sum([a for a in addr.args if not a.structurally_match(base)])

            (count, size) = self._count_size(base)
            prev_len = len(self.state.solver.constraints)
            offset = self.state.solver.eval_one(added % (size // 8), cast_to=int)
            # Don't make the index be a weird '0 // ...' expr if we can avoid it
            if utils.definitely_true(self.state.solver, added == offset):
                index = self.state.solver.BVV(0, 64)
            else:
                index = self.state.solver.simplify((added - offset) / (size // 8))
            return (base, index, offset * 8)

        raise ("B_I_O doesn't know what to do with: " + str(addr) + " of type " + str(type(addr)) + " ; op is " + str(addr.op) + " ; args is " + str(addr.args) + " ; constrs are " + str(self.state.solver.constraints))
