import angr
from angr.sim_type import *
import claripy

# void os_clock_sleep_ns(uint64_t ns);
class os_clock_sleep_ns(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypeNum(64, False)], None, arg_names=["ns"])

    def run(self, ns):
        # TODO reason about sleeps
        pass
