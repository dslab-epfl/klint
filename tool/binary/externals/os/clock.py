# Standard/External libraries
import angr
import claripy

# void os_clock_sleep_ns(uint64_t ns);
class os_clock_sleep_ns(angr.SimProcedure):
    def run(self, ns):
        # TODO reason about sleeps
        pass