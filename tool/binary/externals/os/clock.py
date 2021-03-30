# Standard/External libraries
import angr
import claripy

# Us
from ... import clock as binary_clock

# NOTE: I broke the 'replay' feature while rewriting this, but I'm not sure it matters.

# time_t os_clock_time_ns(void);
# requires emp;
# ensures result != TIME_MAX;
class os_clock_time_ns(angr.SimProcedure):
    def run(self):
        return binary_clock.get_current_time(self.state)

# void os_clock_sleep_ns(uint64_t ns);
class os_clock_sleep_ns(angr.SimProcedure):
    def run(self, ns):
        # TODO reason about sleeps
        pass