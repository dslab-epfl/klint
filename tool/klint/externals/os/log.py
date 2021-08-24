import angr
import claripy

from kalm import utils


# void os_debug(const char* message);
class os_debug(angr.SimProcedure):
    def run(self, message):
        text = self.state.casts.ptr(message)
        py_message = utils.read_str(self.state, message)
        print("DEBUG:", py_message)

class os_debug2(angr.SimProcedure):
    def run(self, val):
        print("DEBUG2:", str(val))
        cst = utils.get_if_constant(self.state.solver, val)
        if cst is not None:
            print(" const:", str(cst))
