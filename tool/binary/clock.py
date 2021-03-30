# Standard/External libraries
import claripy

from . import bitsizes
from . import utils

def get_current_time(state):
    time = claripy.BVS("time", bitsizes.uint64_t)
    #utils.add_constraints_and_check_sat(state, time != 0xFF_FF_FF_FF_FF_FF_FF_FF)
    return time