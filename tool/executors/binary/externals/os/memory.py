import angr
import executors.binary.cast as cast

class MemoryInit(angr.SimProcedure):
  def run(self, count, size):
    # Casts
    count = cast.u64(count)
    size = cast.u64(size)

    # Symbolism assumptions
    if size.symbolic:
      raise angr.AngrExitError("size cannot be symbolic")

    # Postconditions
    return self.state.memory.allocate(count, size, name="allocated", default=self.state.solver.BVV(0, self.state.solver.eval(size, cast_to=int) * 8))
