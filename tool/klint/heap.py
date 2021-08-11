import angr
from angr.state_plugins.plugin import SimStatePlugin
import claripy
from collections import namedtuple

from kalm import utils


# TODO: Only query the fractions map if 'take' has been called at least once for it;
#       but this means there may be maps created during the main loop body, how to handle that?

# All sizes are in bytes, and all offsets are in bits
class HeapPlugin(SimStatePlugin):
    FRACS_NAME = "_fracs"
    Metadata = namedtuple('MapsMemoryMetadata', ['count', 'size', 'fractions'])

    @SimStatePlugin.memo
    def copy(self, memo):
        return self

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True

    def allocate(self, count, size, default=None, name=None, constraint=None):
        max_size = self.state.solver.max(size)
        if max_size > 4096:
            raise Exception("That's a huge block you want to allocate... let's just not: " + str(max_size))

        # Create a map
        name = (name or "memory") + "_addr"
        addr = self.state.maps.new_array(self.state.sizes.ptr, max_size * 8, count, name)

        # Set the default value if needed
        if default is not None:
            if count.structurally_match(claripy.BVV(1, count.size())):
                self.state.maps.set(addr, claripy.BVV(0, self.state.sizes.ptr), default) # simpler
            else:
                self.state.solver.add(self.state.maps.forall(addr, lambda k, v: v == default))

        # Add the constraint if needed
        if constraint is not None:
            self.state.solver.add(self.state.maps.forall(addr, constraint))

        # Add constraints on the addr so it's neither null nor so high it overflows (note the count+1 becaus 1-past-the-array is legal)
        self.state.solver.add(
            addr != 0,
            addr.ULE(claripy.BVV(-1, self.state.sizes.ptr) - ((count + 1) * size))
        )

        # Create the corresponding fractions
        fractions = self.state.maps.new_array(self.state.sizes.ptr, 8, count, name + HeapPlugin.FRACS_NAME)
        self.state.solver.add(self.state.maps.forall(fractions, lambda k, v: v == 100))

        # Record this info
        self.state.metadata.append(addr, HeapPlugin.Metadata(count, size, fractions))

        # Push it through the memory subsystem
        self.state.memory.set_special_object(addr, count, size, self._read, self._write)

        return addr


    def take(self, fraction, ptr): # fraction == None -> take all
        (base, index, offset) = utils.base_index_offset(self.state, ptr, HeapPlugin.Metadata)
        if offset != 0:
            raise Exception("Cannot take at an offset")

        meta = self.state.metadata.get(HeapPlugin.Metadata, base)

        current_fraction, present = self.state.maps.get(meta.fractions, index)
        if fraction is None:
            fraction = current_fraction
        self.state.solver.add(present & current_fraction.UGE(fraction))

        self.state.maps.set(meta.fractions, index, current_fraction - fraction)

        return current_fraction


    def give(self, fraction, ptr):
        (base, index, offset) = utils.base_index_offset(self.state, ptr, HeapPlugin.Metadata)
        if offset != 0:
            raise Exception("Cannot give at an offset")

        meta = self.state.metadata.get(HeapPlugin.Metadata, base)

        current_fraction, present = self.state.maps.get(meta.fractions, index)
        self.state.solver.add(present & (current_fraction + fraction).ULE(100))

        self.state.maps.set(meta.fractions, index, current_fraction + fraction)


    # For invariant inference
    def get_fractions(self, obj):
        meta = self.state.metadata.get_or_none(HeapPlugin.Metadata, obj)
        if meta is None:
            return None
        return meta.fractions
    def is_fractions(self, obj):
        return HeapPlugin.FRACS_NAME in str(obj)


    def _read(self, state, base, index, offset, size):
        meta = self.state.metadata.get(HeapPlugin.Metadata, base)
        fraction, present = self.state.maps.get(meta.fractions, index)
        assert utils.definitely_true(self.state.solver, present & (fraction != 0))
        value, _ = self.state.maps.get(base, index)

        if offset != 0:
            value = value[:offset]

        if value.size() != size * 8:
            value = value[(size*8)-1:0]

        return value


    def _write(self, state, base, index, offset, value):
        meta = self.state.metadata.get(HeapPlugin.Metadata, base)
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

        if value.size() != self.state.maps.value_size(base):
            current, _ = self.state.maps.get(base, index)
            if offset != 0:
                value = value.concat(current[offset-1:0])
            if value.size() != current.size():
                value = current[:value.size()].concat(value)

        self.state.maps.set(base, index, value)
