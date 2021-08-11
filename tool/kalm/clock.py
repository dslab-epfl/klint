import claripy
from collections import namedtuple

frequency_num = claripy.BVS("clock_frequency_num", 8).zero_extend(56)
frequency_denom = claripy.BVV(10, 64) # Ivy Bridge; TODO be more flexible in what CPUs we support...?

TimeMetadata = namedtuple("TimeMetadata", ["time", "cycles"])

def get_time_and_cycles(state):
    if len(state.metadata.get_all(TimeMetadata)) != 0:
        # Reasoning about time gets tricky otherwise.
        # If the code under symbex called the clock twice, which value should be used in the spec? Should the clock even enforce e.g. monotonicity?
        raise Exception("Cannot call the clock twice!")

    time = claripy.BVS("time", state.sizes.uint64_t)
    state.solver.add(time != 0xFF_FF_FF_FF_FF_FF_FF_FF)

    cycles = claripy.BVS("cycles", state.sizes.uint64_t)
    state.solver.add(time == cycles / frequency_num * frequency_denom)

    state.metadata.append(None, TimeMetadata(time, cycles))

    return (time, cycles)