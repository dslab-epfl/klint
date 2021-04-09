from angr.state_plugins import SimSolver
from archinfo.arch_amd64 import ArchAMD64
import datetime
import os
from pathlib import Path

from binary.sizes import SizesPlugin
from binary.executor import CustomSolver

from . import symbex


class _VerifState: pass

def create_state(constraints): 
    state = _VerifState()

    # Angr plugins make some assumptions about structure
    state._get_weakref = lambda: state # for SimStatePlugin.set_state; not really a weakref; whatever
    state._global_condition = None # for the solver
    state.arch = ArchAMD64() # TODO use original arch!

    state.solver = SimSolver()
    state.solver.set_state(state)
    state.solver._stored_solver = CustomSolver()
    state.solver.add(*constraints)

    state.sizes = SizesPlugin()
    state.sizes.set_state(state)

    return state


def verify(data, spec):
    state = create_state(data.constraints)
    state.maps = list(data.maps.values())
    state.path = data.path # useful for debugging
    
    prev_state = create_state(data.prev_constraints)
    prev_state.maps = list(data.prev_maps.values())

    this_folder = Path(__file__).parent.absolute()
    spec_prefix = (this_folder / "spec_prefix.py").read_text()
    spec_utils = (this_folder / "spec_utils.py").read_text()

    full_spec_text = spec_prefix + os.linesep + spec_utils + os.linesep + spec

    # TODO move this somewhere... maybe just use "device_t" since we have time_t and such?
    globals = {
        "Device": "uint16_t"
    }

    for (path, choices) in symbex.symbex(state, prev_state, full_spec_text, "_spec_wrapper", [data], globals):
        print("NF sub-state verified! at", datetime.datetime.now(), path, choices)
    print("NF state verified!")