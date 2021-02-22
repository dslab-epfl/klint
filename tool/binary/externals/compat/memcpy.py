# Standard/External libraries
import angr

# Us
from ... import cast
from ... import utils

# TODO: Is this file still needed?

# TODO: This should not be needed, but because it's considered a builtin by compilers, overriding it is a pain...
# Since the data structures need it, we could just move it to os/memory.h...
class Memcpy(angr.SimProcedure):
    def run(self, dst, src, size):
        self.state.memory.store(dst, self.state.memory.load(src, size, endness=self.state.arch.memory_endness), endness=self.state.arch.memory_endness)
