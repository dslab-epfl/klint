from collections.abc import Iterable
import pickle
from typing import Any, NamedTuple

from angr.sim_state import SimState
from archinfo import Arch
import claripy

from kalm import clock
from klint.externals.os import config as os_config
from klint.externals.net import packet as net_packet


class StateData(NamedTuple):
    arch: Arch
    maps: Any
    constraints: Any
    path: Any
    time: Any
    network: Any
    config: os_config.ConfigMetadata
    devices_count: claripy.ast.bv.BV

    @staticmethod
    def from_state(state: SimState, devices_count: claripy.ast.bv.BV) -> "StateData":
        return StateData(
            arch=state.arch,
            maps=state.maps.get_all(),
            constraints=state.solver.constraints,
            path=state.path,
            time=state.metadata.get_or_none(clock.TimeMetadata, None).time
            if state.metadata.get_or_none(clock.TimeMetadata, None) is not None
            else None,
            network=state.metadata.get_one(net_packet.NetworkMetadata),
            config=(
                state.metadata.get_or_none(os_config.ConfigMetadata, None)
                or os_config.ConfigMetadata({})
            ).items,
            devices_count=devices_count,
        )


def dump_data(
        state_pairs: Iterable[SimState], devices_count: claripy.ast.bv.BV, path: str
) -> None:  # TODO why do we have to move the devices_count around like that? :/
    data = [StateData.from_state(state, devices_count) for state in state_pairs]
    with open(path, "wb") as file:
        pickle.dump(data, file, protocol=4)


def load_data(path: str) -> list[StateData]:
    with open(path, "rb") as file:
        return pickle.load(file)
