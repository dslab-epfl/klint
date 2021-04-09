import angr
import claripy

from ... import utils


# void os_debug(const char* message);
class os_debug(angr.SimProcedure):
    def run(self, message):
        text = self.state.casts.ptr(message)
        py_message = utils.read_str(self.state, message)
        print("DEBUG: " + py_message)
