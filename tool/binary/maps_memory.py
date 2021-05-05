import angr
import claripy
from collections import namedtuple

from binary import utils


# TODO: Only query the fractions map if 'take' has been called at least once for it;
#       but this means there may be maps created during the main loop body, how to handle that?

# All sizes are in bytes, and all offsets are in bits
# We store maps data in the state's memory endianness rather than in self.endness, this makes for fewer flips / more readable constraints
class MapsMemoryMixin(angr.storage.memory_mixins.MemoryMixin):
    FRACS_NAME = "_fracs"
    Metadata = namedtuple('MapsMemoryMetadata', ['count', 'size', 'fractions', 'endness'])

    def load(self, addr, size=None, endness=None, **kwargs):
        if not isinstance(addr, claripy.ast.Base) or not addr.symbolic:
            # Note that further mixins expect addr to be concrete
            return super().load(self.state.solver.eval(addr), size=size, endness=endness, **kwargs)

        (base, index, offset) = utils.base_index_offset(self.state, addr, MapsMemoryMixin.Metadata)

        meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)
        fraction, present = self.state.maps.get(meta.fractions, index)
        assert utils.definitely_true(self.state.solver, present & (fraction != 0))
        data, _ = self.state.maps.get(base, index)

        if endness is not None and endness != meta.endness:
            data = data.reversed

        if offset != 0:
            data = data[:offset]

        if data.size() != size * 8:
            data = data[(size*8)-1:0]

        return data


    def store(self, addr, data, size=None, endness=None, **kwargs):
        if not isinstance(addr, claripy.ast.Base) or not addr.symbolic:
            # Note that further mixins expect addr to be concrete
            super().store(self.state.solver.eval(addr), data, size=size, endness=endness, **kwargs)
            return
        assert size * 8 == data.size(), "Why would you put a custom size???"

        (base, index, offset) = utils.base_index_offset(self.state, addr, MapsMemoryMixin.Metadata)

        meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)
        fraction, present = self.state.maps.get(meta.fractions, index)
        # TODO remove the prints here
        #assert utils.definitely_true(self.state.solver, present & (fraction == 100))
        if not utils.definitely_true(self.state.solver, present & (fraction == 100)):
            print("base, index, offset, fraction, present", base, index, offset, fraction, present)
            print("index", self.state.solver.eval_upto(index, 10))
            print("offset", self.state.solver.eval_upto(offset, 10))
            print("fraction", self.state.solver.eval_upto(fraction, 10))
            print("present", self.state.solver.eval_upto(present, 10))
            assert False

        if data.size() != self.state.maps.value_size(base):
            current, _ = self.state.maps.get(base, index)
            if endness is not None and endness != meta.endness:
                current = current.reversed
            if offset != 0:
                data = data.concat(current[offset-1:0])
            if data.size() != current.size():
                data = current[:data.size()].concat(data)

        if endness is not None and endness != meta.endness:
            data = data.reversed

        self.state.maps.set(base, index, data)
 

    # New method!
    def allocate(self, count, size, default=None, name=None, constraint=None):
        max_size = self.state.solver.max(size)
        if max_size > 4096:
            raise Exception("That's a huge block you want to allocate... let's just not: " + str(max_size))

        name = (name or "memory") + "_addr"
        addr = self.state.maps.new_array(self.state.sizes.ptr, max_size * 8, count, name)
        if default is not None:
            if count.structurally_match(claripy.BVV(1, count.size())):
                self.state.maps.set(addr, claripy.BVV(0, self.state.sizes.ptr), default) # simpler
            else:
                self.state.solver.add(self.state.maps.forall(addr, lambda k, v: v == default))
        if constraint is not None:
            self.state.solver.add(self.state.maps.forall(addr, constraint))
        # neither null nor so high it overflows (note the -1 becaus 1-past-the-array is legal C)
        self.state.solver.add(addr != 0, addr.ULE(claripy.BVV(2**self.state.sizes.ptr-1, self.state.sizes.ptr) - max_size - 1))

        fractions = self.state.maps.new_array(self.state.sizes.ptr, 8, count, name + MapsMemoryMixin.FRACS_NAME)
        self.state.solver.add(self.state.maps.forall(fractions, lambda k, v: v == 100))

        self.state.metadata.append(addr, MapsMemoryMixin.Metadata(count, size, fractions, self.state.arch.memory_endness))

        return addr


    # New method!
    def take(self, fraction, ptr): # fraction == None -> take all
        (base, index, offset) = utils.base_index_offset(self.state, ptr, MapsMemoryMixin.Metadata)
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
        (base, index, offset) = utils.base_index_offset(self.state, ptr, MapsMemoryMixin.Metadata)
        if offset != 0:
            raise Exception("Cannot give at an offset")

        meta = self.state.metadata.get(MapsMemoryMixin.Metadata, base)

        current_fraction, present = self.state.maps.get(meta.fractions, index)
        self.state.solver.add(present & (current_fraction + fraction).ULE(100))

        self.state.maps.set(meta.fractions, index, current_fraction + fraction)


    # For invariant inference
    def get_fractions(self, obj):
        meta = self.state.metadata.get_or_none(MapsMemoryMixin.Metadata, obj)
        if meta is None:
            return None
        return meta.fractions
    def is_fractions(self, obj):
        return MapsMemoryMixin.FRACS_NAME in str(obj)
