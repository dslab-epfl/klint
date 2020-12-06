import angr
import claripy
import binary.bitsizes as bitsizes
from binary.exceptions import SymbexException
from collections import namedtuple

# TODO: This is a hack; it only works because time is only used for the pool, but in general we should model a clock properly...

Time = namedtuple('Time', [])
time_has_merge_func = False

# Pre-initialize so replays go smoothly
original_time = claripy.BVS("time", bitsizes.int64_t)

def get_current_time(state):
    existing = state.metadata.get_all(Time)
    if len(existing) == 0:
        state.metadata.set(original_time, Time())
        return original_time
    # This is only for BPF NFs, won't work for the pool otherwise
    old_time = existing.keys()[0]
    new_time = claripy.BVS('new_time', bitsizes.int64_t)
    state.add_constraints(new_time.SGE(old_time))
    state.metadata.remove_all(Time)
    state.metadata.set(new_time, Time())
    return new_time

def assert_is_current_time(state, time):
    state.metadata.get(Time, time)

def clear(state):
    state.metadata.remove_all(Time)
