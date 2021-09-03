import angr
from angr.state_plugins.plugin import SimStatePlugin
import claripy
from collections import namedtuple

from kalm import utils


# All sizes are in bytes, and all offsets are in bits
class HeapPlugin(SimStatePlugin):
    FRACS_NAME = "_fracs"
    Metadata = namedtuple('MapsMemoryMetadata', ['count', 'size', 'fractions'])

    @SimStatePlugin.memo
    def copy(self, memo):
        return HeapPlugin()

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True

    def allocate(self, count, size, ephemeral=False, default=None, default_fraction=100, addr=None, name=None):
        max_size = self.state.solver.max(size)
        if max_size > 4096:
            raise Exception("That's a huge block you want to allocate... let's just not: " + str(max_size))

        # Create a map
        name = (name or "memory") + "_addr"
        addr = self.state.maps.new_array(self.state.sizes.ptr, max_size * 8, count, name, obj=addr)

        # Set the default value if needed
        if default is not None:
            if count.structurally_match(claripy.BVV(1, count.size())):
                self.state.maps.set(addr, claripy.BVV(0, self.state.sizes.ptr), default) # simpler
            else:
                self.state.solver.add(self.state.maps.forall(addr, lambda k, v: v == default))

        # Add constraints on the addr so it's neither null nor so high it overflows (note the count+1 becaus 1-past-the-array is legal)
        self.state.solver.add(
            addr != 0,
            addr.ULE(claripy.BVV(-1, self.state.sizes.ptr) - ((count + 1) * size))
        )

        # Create the corresponding fractions if needed
        if ephemeral:
            fractions = None
        else:
            fractions = self.state.maps.new_array(self.state.sizes.ptr, 8, count, name + HeapPlugin.FRACS_NAME)
            self.state.solver.add(self.state.maps.forall(fractions, lambda k, v: v == default_fraction))

        # Record this info
        self.state.metadata.append(addr, HeapPlugin.Metadata(count, size, fractions))

        # Push it through the memory subsystem
        self.state.memory.set_special_object(addr, count, size, HeapPlugin._read, HeapPlugin._write)

        return addr


    # TODO: this should be named 'borrow', but then the other must be 'return' and that's not feasible in Python... better name?
    def take(self, fraction, ptr): # fraction == None -> take all
        (base, index, offset) = utils.base_index_offset(self.state, ptr, HeapPlugin.Metadata)
        if offset != 0:
            raise Exception("Cannot borrow at an offset")

        meta = self.state.metadata.get(HeapPlugin.Metadata, base)
        if meta.fractions is None:
            raise Exception("Cannot borrow from an ephemeral allocation")

        current_fraction, present = self.state.maps.get(meta.fractions, index)
        if fraction is None:
            fraction = current_fraction
        assert utils.definitely_true(self.state.solver, present & current_fraction.UGE(fraction))

        self.state.maps.set(meta.fractions, index, current_fraction - fraction)

        return current_fraction


    def give(self, fraction, ptr):
        (base, index, offset) = utils.base_index_offset(self.state, ptr, HeapPlugin.Metadata)
        if offset != 0:
            raise Exception("Cannot release at an offset")

        meta = self.state.metadata.get(HeapPlugin.Metadata, base)
        if meta.fractions is None:
            raise Exception("Cannot release to an ephemeral allocation")

        current_fraction, present = self.state.maps.get(meta.fractions, index)
        assert utils.definitely_true(self.state.solver, present & (current_fraction + fraction).ULE(100))

        self.state.maps.set(meta.fractions, index, current_fraction + fraction)


    # For invariant inference
    def get_fractions(self, obj):
        meta = self.state.metadata.get_or_none(HeapPlugin.Metadata, obj)
        if meta is None:
            return None
        return meta.fractions
    def is_fractions(self, obj):
        return HeapPlugin.FRACS_NAME in str(obj)


    @staticmethod
    def _read(state, base, index, offset, size, reverse_endness):
        meta = state.metadata.get(HeapPlugin.Metadata, base)

        # Handle reads larger than the actual size, e.g. read an uint64_t from an array of uint8_t
        result = claripy.BVV(0, 0)
        while result.size() < size * 8 + offset:
            chunk, present = state.maps.get(base, index)
            # Ensure we can read
            if meta.fractions is None:
                assert utils.definitely_true(state.solver, present)
            else:
                fraction, fraction_present = state.maps.get(meta.fractions, index)
                # fraction_present == present by construction so no need to check both
                assert utils.definitely_true(state.solver, fraction_present & (fraction != 0))
            # Remember the result
            result = chunk.concat(result)
            # Increment the index for the next chunk
            index = index + 1

        if reverse_endness:
            result = result.reversed

        if offset != 0:
            result = result[:offset]

        if result.size() > size * 8:
            result = result[(size*8)-1:0]

        return result

    @staticmethod
    def _write(state, base, index, offset, value, reverse_endness):
        meta = state.metadata.get(HeapPlugin.Metadata, base)

        # We need to handle writes in chunks, e.g. writing an uint64_t to an array of uint8_t
        # This can get messy with the offset, e.g. a 4-bit offset 16-bit write into an 8-bit array should be [4 bits] [8 bits] [4 bits],
        # not [8 bits] [8 bits] both individually offset since they'd span an element and need 2 writes each
        rest = value
        write_size = state.maps.value_size(base)
        while rest.size() != 0:
            if meta.fractions is not None:
                # Ensure we can actually write
                fraction, present = state.maps.get(meta.fractions, index)
                assert utils.definitely_true(state.solver, present & (fraction == 100))
            # The rest may be smaller than the write size, need to account for that
            chunk = rest[min(rest.size(), write_size)-1:0]
            # If we have to write at an offset, which can only happen on the first chunk, we need to write less
            # e.g. instead of an 8-bit write into an 8-bit array, at offset 4 it's a 4-bit write, and at offset 6 it's a 2-bit write
            # but we could already be writing a chunk smaller than the element size, e.g. a 2-bit write at offset 3 into an 8-bit array is still a 2-bit write
            if offset != 0:
                chunk = chunk[min(chunk.size(), write_size-offset)-1:0]
            # Record the rest now, since we might increase the size of the chunk if it's too small for a full write
            # But claripy doesn't allow slicing to go beyond the boundaries, so handle that...
            if chunk.size() < rest.size():
                rest = rest[:chunk.size()]
            else:
                rest = claripy.BVV(0, 0)
            # Handle partial overwrites, for the first and last chunks
            if chunk.size() != write_size:
                current, _ = state.maps.get(base, index)
                if reverse_endness:
                    current = current.reversed
                if offset != 0:
                    chunk = chunk.concat(current[offset-1:0])
                if chunk.size() != current.size():
                    chunk = current[:chunk.size()].concat(chunk)
            if reverse_endness:
                chunk = chunk.reversed
            # Finally we can write
            state.maps.set(base, index, chunk)
            # Increment the index for the next chunk
            index = index + 1
            # All subsequent chunks have no more offset (but the last one may be smaller than the write size)
            offset = 0

