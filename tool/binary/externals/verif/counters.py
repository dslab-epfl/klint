import angr
import claripy

from ... import cast

# size_t counter_create(size_t limit);
class counter_create(angr.SimProcedure):
    def run(self, limit):
        limit = cast.size_t(limit)
        return claripy.If(limit == 8, claripy.BVV(7, self.state.sizes.size_t), claripy.BVV(0, self.state.sizes.size_t))