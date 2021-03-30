# Standard/External libraries
import claripy

from . import bitsizes
from . import utils

frequency_num = claripy.BVS("clock_frequency_num", 8).zero_extend(56)
frequency_denom = claripy.BVV(10, 64) # Ivy Bridge; TODO be more flexible in what CPUs we support...?

def get_current_time(state):
    time = claripy.BVS("time", bitsizes.uint64_t)
    utils.add_constraints_and_check_sat(state, time != 0xFF_FF_FF_FF_FF_FF_FF_FF)
    return time