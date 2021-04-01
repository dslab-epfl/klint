import claripy

from binary import bitsizes
from binary.hash_dict import HashDict

# TODO delete, only for replay?
class SimpleMemory:
    def __init__(self, wrapped):
        self.wrapped = wrapped
        self.stack = HashDict()

    def __getattr__(self, name):
        return getattr(self.wrapped, name)

    def allocate_stack(self, size):
        ptr = claripy.BVS("stack_ptr", bitsizes.size_t)
        value = claripy.BVS("stack_value", size)
        self.stack[ptr] = value
        return ptr

    def load(self, addr, size, endness=None):
        assert addr.symbolic

        stack_value = self.stack[addr]
        if stack_value is None:
            assert size is not None, "this should never happen"
            return self.wrapped.load(addr, size, endness=endness)
        return stack_value

    def store(self, addr, data, endness=None):
        assert addr.symbolic

        if addr in self.stack:
            self.stack[addr] = data
        else:
            self.wrapped.store(addr, data, endness=endness)