# Standard/External libraries
import angr
import claripy
from collections import namedtuple

# Us
from .exceptions import SymbexException
from . import bitsizes
from . import utils

# TODO: Only query the fractions map if 'take' has been called at least once for it; but this means the metadata may not be the same before/after init, how to handle that?

class MapsMemoryMixin(angr.storage.memory_mixins.MemoryMixin):
    FRACS_NAME = "_fracs"
    Metadata = namedtuple('MapsMemoryMetadata', ['count', 'size', 'fractions'])

    def load(self, addr, size=None, endness=None, **kwargs):
        if not isinstance(addr, claripy.ast.Base) or not addr.symbolic:
            return super().load(addr, size=size, endness=endness, **kwargs)

        (base, index, offset) = self._base_index_offset(addr)

        meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)
        fraction = self.state.maps.get(meta.fractions, index)
        if utils.can_be_true(self.state.solver, fraction == 0):
            raise SymbexException("Attempt to load without definitely having access to the object at addr " + str(addr) + " ; fraction is " + str(fraction) + " ; constraints are " + str(self.state.solver.constraints) + " ; e.g. could be " + str(self.state.solver.eval_upto(fraction, 10, cast_to=int)))
        
        value = self.state.maps.get(base, index)

        if endness is not None and endness != self.endness:
            value = value.reversed

        if offset != 0:
            value = value[value.size()-1:offset]

        if size is not None and value.size() != size:
            value = value[size-1:0]

        return value


    def store(self, addr, data, size=None, endness=None, **kwargs):
        if not isinstance(addr, claripy.ast.Base) or not addr.symbolic:
            super().store(addr, data, size=size, endness=endness, **kwargs)
            return
        assert size is None or size * 8 == data.size(), "Why would you not put a custom size???"

        (base, index, offset) = self._base_index_offset(addr)

        meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)
        fraction = self.state.maps.get(meta.fractions, index)
        if utils.can_be_true(self.state.solver, fraction != 100):
            raise SymbexException("Attempt to store without definitely owning the object at addr " + str(request.addr) + " ; fraction is " + str(fraction) + " ; constraints are " + str(self.state.solver.constraints) + " ; e.g. could be " + str(self.state.solver.eval_upto(fraction, 10, cast_to=int)))

        if endness is not None and endness != self.endness:
            data = data.reversed

        if offset != 0 or data.size() != self.state.maps.value_size(addr):
            current = self.state.maps.get(addr, index)
            if offset != 0:
                data = data.concat(current[offset-1:0])
            if data.size() != self.state.maps.value_size(addr):
                data = current[current.size()-1:data.size()].concat(data)

        self.state.maps.set(addr, index, data)
 

    # New method!
    def allocate(self, count, size, default=None, name=None, constraint=None):
        max_size = self.state.solver.max(size)
        if max_size > 4096:
            raise SymbexException("That's a huge block you want to allocate... let's just not: " + str(max_size))

        name = (name or "memory") + "_addr"
        addr = self.state.maps.new_array(bitsizes.ptr, max_size * 8, count, name)
        if default is not None:
            if count.structurally_match(claripy.BVV(1, count.size())):
                self.state.maps.set(addr, claripy.BVV(0, bitsizes.ptr), default) # simpler
            else:
                self.state.add_constraints(self.state.maps.forall(addr, lambda k, v: v == default))
        if constraint is not None:
            self.state.add_constraints(self.state.maps.forall(addr, constraint))
        # neither null nor so high it overflows (note the -1 becaus 1-past-the-array is legal C)
        self.state.add_constraints(addr != 0, addr.ULE(claripy.BVV(2**bitsizes.ptr-1, bitsizes.ptr) - max_size * 8 - 1))

        fractions = self.state.maps.new_array(bitsizes.ptr, 8, count, name + MapsMemoryMixin.FRACS_NAME)

        self.state.metadata.set(addr, MapsMemoryMixin.Metadata(count, size, fractions))

        return result


    # New method!
    def take(self, fraction, ptr): # fraction == None -> take all
        (base, index, offset) = self._base_index_offset(ptr)
        if offset != 0:
            raise SymbexException("Cannot take at an offset")

        meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)

        current_fraction = self.state.maps.get(meta.fractions, index)
        if fraction is None:
            fraction = current_fraction

        if utils.can_be_true(self.state.solver, current_fraction.ULT(fraction)):
            raise SymbexException("Cannot take " + str(fraction) + " ; there is only " + str(current_fraction))

        self.state.maps.set(meta.fractions, index, current_fraction - fraction)

        return current_fraction


    # New method!
    def give(self, fraction, ptr):
        (base, index, offset) = self._base_index_offset(ptr)
        if offset != 0:
            raise SymbexException("Cannot give at an offset")

        meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)

        current_fraction = self.state.maps.get(meta.fractions, index)
        if utils.can_be_true(self.state.solver, (current_fraction + fraction).UGT(100)):
            raise SymbexException("Cannot give " + str(fraction) + " ; there is already " + str(current_fraction))

        self.state.maps.set(meta.fractions, index, current_fraction + fraction)

    # DIRTY HACK for invariant inference
    def get_obj_and_size_from_fracs_obj(self, fracs_obj):
        if MapsMemoryMixin.FRACS_NAME not in str(fracs_obj):
            return (None, None)
        for (o, meta) in self.state.metadata.get_all(MapsMemoryMixin.Metadata):
            if meta.fractions is fracs_obj:
                return (o, meta.size)
        raise SymbexException("What are you doing?")

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
                base = [b for b in base if any(True for (a, _, __) in self.segments if b.structurally_match(a))]
                if len(base) == 1:
                    base = base[0]
                else:
                    raise SymbexException("!= 1 candidate for base??? are you symbolically indexing a global variable or something?")
            added = sum([a for a in addr.args if not a.structurally_match(base)])

            meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)
            offset = self.state.solver.eval_one(added % (meta.size // 8), cast_to=int)
            # Don't make the index be a weird '0 // ...' expr if we can avoid it
            if utils.definitely_true(self.state.solver, added == offset):
                index = claripy.BVV(0, 64)
            else:
                index = (added - offset) / (meta.size // 8)
            return (base, index, offset * 8)

        addr = self.state.solver.simplify(addr) # this handles the descriptor addresses, which are split between two NIC registers
        if addr.op == "BVS":
            return (addr, claripy.BVV(0, 64), 0)

        raise SymbexException("B_I_O doesn't know what to do with: " + str(addr) + " of type " + str(type(addr)) + " ; op is " + str(addr.op) + " ; args is " + str(addr.args) + " ; constrs are " + str(self.state.solver.constraints))
