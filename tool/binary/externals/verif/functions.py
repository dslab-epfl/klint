# Standard/External libraries
import angr
import claripy

# Us
from ... import bitsizes
from ... import cast
from ... import utils
from ...exceptions import SymbexException

# typedef void foreach_index_function(size_t index, void* state);
# void foreach_index(size_t length, foreach_index_function* func, void* state);
class foreach_index(angr.SimProcedure):
    def run(self, length, func, st):
        length = cast.size_t(length)
        func = cast.ptr(func)
        st = cast.ptr(st)

        if func.op != 'BVV':
            raise SymbexException("Function pointer cannot be symbolic")

        def case_zero(state):
            pass

        def case_nonzero(state):
            index = claripy.BVS("foreach_index", bitsizes.size_t)
            utils.add_constraints_and_check_sat(self.state, index.ULT(length))
            func_state = self.state.project.factory.call_state(func.args[0], *[index, st], base_state=self.state)
            func_sm = self.state.project.factory.simulation_manager(func_state)
            func_sm.use_technique(angr.exploration_techniques.DFS())
            func_sm.run()
            if len(func_sm.errored) > 0:
                func_sm.errored[0].reraise()
            print("ok")

        return utils.fork_guarded(self, self.state, length == 0, case_zero, case_nonzero)