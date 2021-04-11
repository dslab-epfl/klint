import claripy
from collections import namedtuple

from . import utils

frequency_num = claripy.BVS("clock_frequency_num", 8).zero_extend(56)
frequency_denom = claripy.BVV(10, 64) # Ivy Bridge; TODO be more flexible in what CPUs we support...?

# TODO this is a mess; maybe just move to a model where we always provide the time? with rdtsc it might be ok for perf? check...
Times = namedtuple("Times", ["values"])

def get_current_cycles(state):
    time = claripy.BVS("time", state.sizes.uint64_t)
    state.solver.add(time != 0xFF_FF_FF_FF_FF_FF_FF_FF)

    times = state.metadata.get(Times, None, default_init=lambda: Times([]))
    # TODO should we? doesn't appear necessary for now
    #if len(times.values) > 0:
    #    state.solver.add(time >= times.values[-1])
    times.values.append(time)
    return time