from angr.state_plugins import SimSolver
from archinfo.arch_amd64 import ArchAMD64
import datetime
import os
from pathlib import Path

from binary import clock
from binary.sizes import SizesPlugin
from binary.executor import CustomSolver

from . import symbex


class _VerifState:
    def __init__(self, constraints, maps, path):
        # Angr plugins make some assumptions about structure
        self._get_weakref = lambda: self # for SimStatePlugin.set_state; not really a weakref; whatever
        self._global_condition = None # for the solver
        self.arch = ArchAMD64() # TODO use original arch!

        self.sizes = SizesPlugin()
        self.sizes.set_state(self)

        self.solver = SimSolver()
        self.solver.set_state(self)
        self.solver._stored_solver = CustomSolver()
        self.solver.add(*constraints)

        self.maps = maps
        self.path = path

    def copy(self):
        return _VerifState(self.solver.constraints, self.maps, self.path)


def verify(all_data, spec):
    this_folder = Path(__file__).parent.absolute()
    spec_prefix = (this_folder / "spec_prefix.py").read_text()
    spec_utils = (this_folder / "spec_utils.py").read_text()

    full_spec_text = spec_prefix + os.linesep + spec_utils + os.linesep + spec

    globals = {
        # TODO move this somewhere... maybe just use "device_t" since we have time_t and such?
        "Device": "uint16_t"
    }
    
    state_data = [(
        _VerifState(data.constraints, data.maps, data.path), # state; path is useful for debugging
        _VerifState(data.prev_constraints, data.prev_maps, None), # prev_state
        [data] # args
    ) for data in all_data]
    (choices, results) = symbex.symbex(full_spec_text, "_spec_wrapper", globals, state_data)
    print("NF state verified! at", datetime.datetime.now(), choices, results)