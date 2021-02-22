# Standard/External libraries
import angr
import claripy

# Us
from ... import cast
from ... import utils


# _Noreturn void os_exit(void);
class os_exit(angr.SimProcedure):
    def run(self):
        # This works because we only allow os_exit during init, and we discard unsat init states
        self.state.add_constraints(claripy.false)

# void os_debug(const char* message);
class os_debug(angr.SimProcedure):
    def run(self, message):
        text = cast.ptr(message)
        py_message = utils.read_str(self.state, message)
        print("DEBUG: " + py_message)
