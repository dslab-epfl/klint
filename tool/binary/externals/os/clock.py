# Standard/External libraries
import angr
import claripy

# Us
from ... import bitsizes

# NOTE: I broke the 'replay' feature while rewriting this, but I'm not sure it matters.

# time_t os_clock_time_ns(void);
# requires emp;
# ensures result != TIME_MAX;
class os_clock_time_ns(angr.SimProcedure):
    def run(self):
        result = claripy.BVS("time", bitsizes.uint64_t)
        utils.add_constraints_and_check_sat(self.state, result != 0xFF_FF_FF_FF_FF_FF_FF_FF)
        return result

# void os_clock_sleep_ns(uint64_t ns);
class os_clock_sleep_ns(angr.SimProcedure):
    def run(self, ns):
        # TODO reason about sleeps
        pass