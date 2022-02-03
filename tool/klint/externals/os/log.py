import angr
from angr.sim_type import *

from kalm import utils


# void os_debug(const char* message);
class os_debug(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeChar())], None, arg_names=["message"])

    def run(self, message):
        py_message = utils.read_str(self.state, message)
        print("DEBUG:", py_message)
