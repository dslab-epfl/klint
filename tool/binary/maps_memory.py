import angr
import claripy
from collections import namedtuple

from . import bitsizes
from . import utils

# TODO: Only query the fractions map if 'take' has been called at least once for it; but this means the metadata may not be the same before and after init, how to handle that?

# General note: we ignore presence bits when if they are false then the fractions checks will definitely fail
# Also, recall that all sizes are in bytes, and all offsets are in bits
class MapsMemoryMixin(angr.storage.memory_mixins.MemoryMixin):
    FRACS_NAME = "_fracs"
    Metadata = namedtuple('MapsMemoryMetadata', ['count', 'size', 'fractions'])

    def load(self, addr, size=None, endness=None, **kwargs):
        if not isinstance(addr, claripy.ast.Base) or not addr.symbolic:
            # Note that further mixins expect addr to be concrete
            return super().load(self.state.solver.eval(addr), size=size, endness=endness, **kwargs)

        (base, index, offset) = self._base_index_offset(addr)

        meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)
        fraction, present = self.state.maps.get(meta.fractions, index)
        self.state.solver.add(present & (fraction != 0))
        data, _ = self.state.maps.get(base, index)

        if endness is not None and endness != self.endness:
            data = data.reversed

        if offset != 0:
            data = data[data.size()-1:offset]

        if data.size() != size * 8:
            data = data[(size*8)-1:0]

        return data


    def store(self, addr, data, size=None, endness=None, **kwargs):
        if not isinstance(addr, claripy.ast.Base) or not addr.symbolic:
            # Note that further mixins expect addr to be concrete
            super().store(self.state.solver.eval(addr), data, size=size, endness=endness, **kwargs)
            return
        assert size * 8 == data.size(), "Why would you not put a custom size???"

        (base, index, offset) = self._base_index_offset(addr)

        meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)
        fraction, present = self.state.maps.get(meta.fractions, index)
        self.state.solver.add(present & (fraction == 100))

        if data.size() != self.state.maps.value_size(base):
            current, _ = self.state.maps.get(base, index)
            if endness is not None and endness != self.endness:
                current = current.reversed
            if offset != 0:
                data = data.concat(current[offset-1:0])
            if data.size() != current.size():
                data = current[current.size()-1:data.size()].concat(data)

        if endness is not None and endness != self.endness:
            data = data.reversed

        self.state.maps.set(base, index, data, UNSAFE_can_flatten=True) # memory cannot escape to an invariant aside from v0 thus this is safe)
 

    # New method!
    def allocate(self, count, size, default=None, name=None, constraint=None):
        max_size = self.state.solver.max(size)
        if max_size > 4096:
            raise Exception("That's a huge block you want to allocate... let's just not: " + str(max_size))

        name = (name or "memory") + "_addr"
        addr = self.state.maps.new_array(bitsizes.ptr, max_size * 8, count, name)
        if default is not None:
            if count.structurally_match(claripy.BVV(1, count.size())):
                self.state.maps.set(addr, claripy.BVV(0, bitsizes.ptr), default) # simpler
            else:
                self.state.solver.add(self.state.maps.forall(addr, lambda k, v: v == default))
        if constraint is not None:
            self.state.solver.add(self.state.maps.forall(addr, constraint))
        # neither null nor so high it overflows (note the -1 becaus 1-past-the-array is legal C)
        self.state.solver.add(addr != 0, addr.ULE(claripy.BVV(2**bitsizes.ptr-1, bitsizes.ptr) - max_size - 1))

        fractions = self.state.maps.new_array(bitsizes.ptr, 8, count, name + MapsMemoryMixin.FRACS_NAME)
        self.state.solver.add(self.state.maps.forall(fractions, lambda k, v: v == 100))

        self.state.metadata.append(addr, MapsMemoryMixin.Metadata(count, size, fractions))

        return addr


    # New method!
    def take(self, fraction, ptr): # fraction == None -> take all
        (base, index, offset) = self._base_index_offset(ptr)
        if offset != 0:
            raise Exception("Cannot take at an offset")

        meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)

        current_fraction, present = self.state.maps.get(meta.fractions, index)
        if fraction is None:
            fraction = current_fraction
        self.state.solver.add(present & current_fraction.UGE(fraction))

        self.state.maps.set(meta.fractions, index, current_fraction - fraction)

        return current_fraction


    # New method!
    def give(self, fraction, ptr):
        (base, index, offset) = self._base_index_offset(ptr)
        if offset != 0:
            raise Exception("Cannot give at an offset")

        meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)

        current_fraction, present = self.state.maps.get(meta.fractions, index)
        self.state.solver.add(present & (current_fraction + fraction).ULE(100))

        self.state.maps.set(meta.fractions, index, current_fraction + fraction)

    # DIRTY HACK for invariant inference
    def get_obj_and_size_from_fracs_obj(self, fracs_obj):
        if MapsMemoryMixin.FRACS_NAME not in str(fracs_obj):
            return (None, None)
        for (o, meta) in self.state.metadata.get_all(MapsMemoryMixin.Metadata).items():
            if meta.fractions is fracs_obj:
                return (o, meta.size)
        raise Exception("What are you doing?")

    # TODO this should not exist
    def havoc(self, addr):
        (base, index, offset) = self._base_index_offset(addr)
        self.state.maps.havoc(base, None, True)
        # don't havoc fractions, the notion of fractions doesn't really make sense with userspace BPF anyway, which this is for


    # Guarantees that:
    # - Result is of the form (base, index, offset)
    # - 'base': BV, is a symbolic pointer, but "concrete" here in that it must be exactly 1 pointer
    # - 'index': BV, is a symbolic index, could be anything
    # - 'offset': int, is an offset in bits, concrete
    def _base_index_offset(self, addr):
        def as_simple(val):
            if val.op == "BVS": return val
            if val.op == '__add__' and len(val.args) == 1: return as_simple(val.args[0])
            if val.op == 'Extract': return val
            return None

        simple_addr = as_simple(addr)
        if simple_addr is not None:
            return (simple_addr, claripy.BVV(0, 64), 0) # Directly addressing a base, i.e., base[0]

        if addr.op == '__add__':
            base = [a for a in map(as_simple, addr.args) if a is not None]

            if len(base) == 0:
                # let's hope this can be solved by simplifying?
                addr = self.state.solver.simplify(addr)
                base = [a for a in map(as_simple, addr.args) if a is not None]

            if len(base) == 1:
                base = base[0]
            else:
                base = [b for b in base if any(b.structurally_match(k) for k in self.state.metadata.get_all(MapsMemoryMixin.Metadata).keys())]
                if len(base) == 1:
                    base = base[0]
                else:
                    raise Exception("!= 1 candidate for base??? are you symbolically indexing a global variable or something?")
            added = sum([a for a in addr.args if not a.structurally_match(base)])

            meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)
            offset = self.state.solver.eval_one(modulo_simplify(added, meta.size), cast_to=int)
            # Don't make the index be a weird '0 // ...' expr if we can avoid it, but don't call the solver for that
            if (added == offset).is_true():
                index = claripy.BVV(0, 64)
            else:
                index = (added - offset) // meta.size
            return (base, index, offset * 8)

        addr = self.state.solver.simplify(addr) # this handles the descriptor addresses, which are split between two NIC registers
        if addr.op == "BVS":
            return (addr, claripy.BVV(0, 64), 0)

        raise Exception("B_I_O doesn't know what to do with: " + str(addr) + " of type " + str(type(addr)) + " ; op is " + str(addr.op) + " ; args is " + str(addr.args) + " ; constrs are " + str(self.state.solver.constraints))


# Optimization: the "modulo_simplify" function allows MapsMemoryMixin to avoid calling the solver when computing the offset of a memory access

# Returns a dictionary such that ast == sum(e.ast * m for (e, m) in result.items())
def as_mult_add(ast):
    if ast.op == '__lshift__':
        nested = as_mult_add(ast.args[0])
        return {e: m << ast.args[1] for (e, m) in nested.items()}
    if ast.op == '__add__' or ast.op == '__sub__':
        coeff = 1
        result = {}
        for arg in ast.args:
            nested = as_mult_add(arg)
            for e, m in nested.items():
                result.setdefault(e, 0)
                result[e] += coeff * m
            coeff = 1 if ast.op == '__add__' else -1
        return result
    if ast.op == '__mul__':
        lone_sym = None
        con = None
        for arg in ast.args:
            if arg.symbolic:
                if lone_sym is not None:
                    break
                lone_sym = arg
            else:
                # Avoid introducing "1 * ..." terms
                if con is None:
                    con = arg
                else:
                    con *= arg
        else:
            if con is None:
                return as_mult_add(lone_sym)
            else:
                return {e: m * con for (e, m) in as_mult_add(lone_sym).items()}
    return {ast.cache_key: 1}

# Returns a simplified form of a % b
def modulo_simplify(a, b):
    result = 0
    for (e, m) in as_mult_add(a).items():
        # note that is_true just performs basic checks, so if as_mult_add decomposed it nicely, we'll skip the modulo entirely
        # e.g. (x * 4) % 2 can be simplified to 0
        if not (e.ast % b == claripy.BVV(0, a.size())).is_true() and not (m % b == claripy.BVV(0, a.size())).is_true():
            result += e.ast * m
    return result % b