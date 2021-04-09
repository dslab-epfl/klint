from collections import namedtuple
import pickle

from binary import clock
from binary.externals.os import config as os_config
from binary.externals.net import packet as net_packet

StateData = namedtuple('StateData', ['arch', 'maps', 'constraints', 'prev_maps', 'prev_constraints', 'path', 'times', 'network', 'config', 'devices_count'])

def dump_data(state_pairs, devices_count, path): # TODO why do we have to move the devices_count around like that? :/
    data = [StateData(
        arch = state.arch,
        maps = {k: v.flatten(keep_known_items=True) for (k, v) in state.maps.get_all().items()},
        constraints = state.solver.constraints,
        prev_maps = {k: v.flatten(keep_known_items=True) for (k, v) in prev_state.maps.get_all().items()},
        prev_constraints = prev_state.solver.constraints,
        path = state.path,
        times = (state.metadata.get_or_none(clock.Times, None) or clock.Times([])).values,
        network = state.metadata.get_one(net_packet.NetworkMetadata),
        config = (state.metadata.get_or_none(os_config.ConfigMetadata, None) or os_config.ConfigMetadata({})).items,
        devices_count = devices_count
    ) for (prev_state, state) in state_pairs]
    with open(path, "wb") as file:
        pickle.dump(data, file, protocol=4)

def load_data(path):
    with open(path, "rb") as file:
        return pickle.load(file)