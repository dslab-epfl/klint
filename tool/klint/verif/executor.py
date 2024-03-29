from collections.abc import Callable
from angr.state_plugins import SimSolver
from archinfo.arch_amd64 import ArchAMD64
import claripy
import copy
import datetime
import itertools
import os
from pathlib import Path

from kalm.plugins.sizes import SizesPlugin
from kalm.solver import KalmSolver

from klint import ghostmaps
from klint import statistics
from klint.verif import symbex
from klint.verif.persistence import StateData


class _VerifMaps:
    def __init__(self, maps):
        self._maps = maps

    def __getitem__(self, obj):
        return next(m for (o, m) in self._maps if o.structurally_match(obj))

    def __iter__(self):
        return iter(self._maps)

class _VerifState:
    def __init__(self, constraints, maps, path):
        # Angr plugins make some assumptions about structure
        self._get_weakref = lambda: self # for SimStatePlugin.set_state; not really a weakref; whatever
        self._global_condition = None # for the solver
        self.arch = ArchAMD64() # TODO use original arch!

        # Allow the spec to create a BV without importing claripy explicitly
        self.BVS = claripy.BVS
        self.BVV = claripy.BVV
        # Allow the spec to create MapHas as well, for packet.data's ==
        self.MapHas = ghostmaps.MapHas

        self.sizes = SizesPlugin()
        self.sizes.set_state(self)

        self.solver = SimSolver()
        self.solver.set_state(self)
        self.solver._stored_solver = KalmSolver()
        self.solver.add(*constraints)

        self.maps = _VerifMaps(maps)
        self.path = path

    def copy(self):
        return _VerifState(self.solver.constraints.copy(), copy.deepcopy(self.maps._maps), copy.deepcopy(self.path))


def verify(all_data: list[StateData], spec: Callable[..., None]) -> None:
    claripy.ast.base.var_counter = itertools.count(1000000)

    print("Verifying NF's", len(all_data), "states at", datetime.datetime.now())
    statistics.work_start("verif")
    state_data = [(
        _VerifState(data.constraints, data.maps, data.path), # path is useful for debugging
        data # args
    ) for data in all_data]
    (choices, results) = symbex.symbex(spec, state_data)
    statistics.work_end()
    print("NF verified! at", datetime.datetime.now())
