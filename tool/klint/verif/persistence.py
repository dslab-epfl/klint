from collections import namedtuple
import pickle

from kalm import clock
from klint.externals.os import config as os_config
from klint.externals.net import packet as net_packet

StateData = namedtuple('StateData', ['arch', 'maps', 'constraints', 'path', 'time', 'network', 'config', 'devices_count'])

def dump_data(state_pairs, devices_count, path): # TODO why do we have to move the devices_count around like that? :/
    data = [StateData(
        arch = state.arch,
        maps = state.maps.get_all(),
        constraints = state.solver.constraints,
        path = state.path,
        time = state.metadata.get_or_none(clock.TimeMetadata, None).time if state.metadata.get_or_none(clock.TimeMetadata, None) is not None else None,
        network = state.metadata.get_one(net_packet.NetworkMetadata),
        config = (state.metadata.get_or_none(os_config.ConfigMetadata, None) or os_config.ConfigMetadata({})).items,
        devices_count = devices_count
    ) for state in state_pairs]
    with open(path, "wb") as file:
        pickle.dump(data, file, protocol=4)

def load_data(path):
    with open(path, "rb") as file:
        return pickle.load(file)