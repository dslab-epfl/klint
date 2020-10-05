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
        # how to handle it:
        # - store all the times we've given
        # - during spec matching, return those times at each call to the clock
        raise SymbexException("Sorry, calling clock multiple times is not handled yet")
    time = claripy.BVS('time', bitsizes.int64_t)
    state.metadata.set(time, Time())
    return time

def assert_is_current_time(state, time):
    state.metadata.get(Time, time)

def clear(state):
    state.metadata.remove_all(Time)
