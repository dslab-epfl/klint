# Standard/External libraries
import angr
import claripy

# Us
from ... import cast
from ... import utils


# void os_debug(const char* message);
class os_debug(angr.SimProcedure):
    def run(self, message):
        text = cast.ptr(message)
        py_message = utils.read_str(self.state, message)
        print("DEBUG: " + py_message)
