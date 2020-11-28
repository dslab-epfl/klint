import angr
import claripy
import binary.bitsizes as bitsizes
from binary.exceptions import SymbexException
from collections import namedtuple

# TODO: This is a hack; it only works because time is only used for the dchain, but in general we should model a clock properly...

Time = namedtuple('Time', [])
time_has_merge_func = False

def get_current_time(state):
    existing = state.metadata.get_all(Time)
    if len(existing) != 0:
        # TODO: Make sure this is OK? Should be cause the dchain wants <= and in general the time only has to be monotonic
        return existing.keys()[0]
    time = claripy.BVS('time', bitsizes.int64_t)
    state.metadata.set(time, Time())
    return time

def assert_is_current_time(state, time):
    state.metadata.get(Time, time)

def clear(state):
    state.metadata.remove_all(Time)
