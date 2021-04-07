import angr
import claripy

from ... import bitsizes
from ... import cast

# size_t counter_create(size_t limit);
class counter_create(angr.SimProcedure):
    def run(self, limit):
        limit = cast.size_t(limit)
        return claripy.If(limit == 8, claripy.BVV(7, bitsizes.size_t), claripy.BVV(0, bitsizes.size_t))