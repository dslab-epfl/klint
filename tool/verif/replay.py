import claripy
from collections import namedtuple
from datetime import datetime
import inspect
import os
from pathlib import Path

from .common import *
from .memory_simple import SimpleMemory
from .replay import *
from binary import bitsizes
from binary import utils
from binary.externals.os import config as os_config
from binary.externals.os import memory as os_memory
from binary.externals.os import network as os_network
from binary.externals.os import structs as os_structs
from binary.ghost_maps import *
from binary.memory_fractional import FractionalMemory, RecordAllocateOpaque
from binary.metadata import MetadataPlugin
from binary.path import PathPlugin
from python import executor as py_executor


class ReplayException(Exception): pass

def expect(state, expected):
    while True:
        actual = state.path.ghost_dequeue()
        if type(expected) == type(actual):
            ed = expected._asdict()
            ad = actual._asdict()
            if all(ed[k] is None or str(ed[k]) == str(ad[k]) for k in ed.keys()):
                return actual
        if not isinstance(actual, RecordGet):
            raise ReplayException(f"Replay: expected {expected} but got {actual}")


class SymbolFactoryReplayPlugin:
    def __init__(self, history):
        self.history = history
        self.index = 0

    def dequeue(self):
        result = self.history[self.index]
        self.index = self.index + 1
        return result

    def BVS(self, name, size):
        (actual_name, result) = self.dequeue()
        if actual_name == name:
            return result
        raise ReplayException(f"BVS replay: expected {name} but got {actual_name}")
    
class MemoryAllocateOpaqueReplayPlugin:
    def __init__(self, wrapped):
        self.wrapped = wrapped

    def __getattr__(self, name):
        return getattr(self.wrapped, name)

    def allocate_opaque(self, name):
        return expect(self.wrapped.state, RecordAllocateOpaque(name, None)).result

class GhostMapsReplayPlugin:
    def __init__(self, state):
        self.state = state
        self.metas = {}

    def new(self, key_size, value_size, name="map"):
        obj = self.state.memory.allocate_opaque(name)
        expect(self.state, RecordNew(key_size, value_size, obj))
        self.metas[obj] = MapMeta(name, key_size, value_size)
        return obj

    def new_array(self, key_size, value_size, length, name="map"):
        obj = self.state.memory.allocate_opaque(name)
        expect(self.state, RecordNewArray(key_size, value_size, length, obj))
        self.metas[obj] = MapMeta(name, key_size, value_size)
        return obj

    def length(self, obj):
        return expect(self.state, RecordLength(obj, None)).result

    def key_size(self, obj):
        return self.metas[obj].key_size

    def value_size(self, obj):
        return self.metas[obj].value_size

    def get(self, obj, key, value=None, from_present=True):
        return expect(self.state, RecordGet(obj, key, None)).result

    def set(self, obj, key, value):
        expect(self.state, RecordSet(obj, key, value))

    def remove(self, obj, key):
        expect(self.state, RecordRemove(obj, key))

    def forall(self, obj, pred):
        record = expect(self.state, RecordForall(obj, None, None, None, None))
        if str(pred(record.pred_key, record.pred_value)) == str(record.pred): # idk why but structurally_match seems to fail for no reason
            return record.result
        raise ReplayException(f"Forall replay: expected {record.pred} but got {pred(record.pred_key, record.pred_value)}")

    def havoc(self, obj, max_length, is_array):
        pass # ignore for now...



def init_network_if_needed(state):
    if current_state.metadata.get_unique(os_network.NetworkMetadata) is None:
        os_network.packet_init(current_state, current_devices_count)

def ptr_alloc(state, type):
    size = type_size(type)
    return state.memory.allocate_stack(size)

def ptr_read(state, ptr, type=None):
    if type is None:
        size = None # -> we allocated it in ptr_alloc
    else:
        size = type_size(type) // 8
    result = state.memory.load(ptr, size, endness=state.arch.memory_endness)
    if type is None:
        return result
    return type_cast(result, type)

def transmit(state, packet, device):
    global current_outputs
    current_outputs.append((packet.data, packet.length, device))
    state.memory.take(None, packet._data_addr, None) # mimic what the real transmit does

# === End spec helpers === #

externals = {
    # Spec helpers
    "ptr_alloc": ptr_alloc,
    "ptr_read": ptr_read,
    "type_size": type_size,
    # Path equivalence check helpers
    "transmit": transmit,
    "os_memory_alloc": os_memory.OsMemoryAlloc,
    "os_map_alloc": os_structs.map.OsMapAlloc,
    "os_map_get": os_structs.map.OsMapGet,
    "os_map_set": os_structs.map.OsMapSet,
    "os_map_remove": os_structs.map.OsMapRemove,
    "os_pool_alloc": os_structs.pool.OsPoolAlloc,
    "os_pool_borrow": os_structs.pool.OsPoolBorrow,
    "os_pool_return": os_structs.pool.OsPoolReturn,
    "os_pool_refresh": os_structs.pool.OsPoolRefresh,
    "os_pool_expire": os_structs.pool.OsPoolExpire,
    "lpm_alloc": os_structs.lpm.LpmAlloc,
    "lpm_lookup_elem": os_structs.lpm.LpmLookupElem
}

def handle_externals(name, *args, **kwargs):
    global current_state
    global current_devices_count

    ext = externals[name]
    if inspect.isclass(ext): # it's a SimProcedure
        # HACK: init the packet at the right time
        if "alloc" not in name:
            init_network_if_needed(current_state)
        ext_inst = ext()
        ext_inst.state = current_state
        args = [a if isinstance(a, claripy.ast.base.Base) else claripy.BVV(a, bitsizes.size_t) for a in args]
        result = ext_inst.run(*args)
        if result.size() == bitsizes.bool and not result.symbolic:
            return not result.structurally_match(claripy.BVV(0, bitsizes.bool))
        return result
    else:
        return ext(current_state, *args)

def verify(data, spec):
    if 'predefs_text' not in globals():
        global predefs_text
        predefs_text = Path(os.path.dirname(os.path.realpath(__file__)) + "/spec_predefs.py").read_text()
    full_spec = predefs_text + "\n\n\n" + spec

    global current_state
    current_state = create_angr_state(data.constraints)
    current_state.maps = GhostMapsReplayPlugin(current_state, data.maps)
    current_state.metadata = MetadataPlugin()
    current_state.path = PathPlugin([], data.ghost_history)
    current_state.symbol_factory =  SymbolFactoryReplayPlugin(data.symbol_history)
    current_state.memory = SimpleMemory(MemoryAllocateOpaqueReplayPlugin(current_state.memory))

    global current_devices_count
    current_devices_count = data.devices_count

    global current_outputs
    current_outputs = []

    packet = SpecPacket(current_state, data.network)

    py_executor.execute(
        spec_text=full_spec,
        spec_fun_name="spec",
        spec_args=[packet, data.config, data.devices_count],
        spec_external_names=externals.keys(),
        spec_external_handler=handle_externals
    )

    # in case it wasn't done during the execution (see HACK above)
    init_network_if_needed(current_state)

    current_state.path.ghost_free([RecordGet, RecordForall, RecordLength])
    if len(current_state.path.ghost_get_remaining()):
        raise VerificationException(f"There are operations remaining: {current_state.path.ghost_get_remaining()}")

    expected_outputs = data.network.transmitted

    if len(expected_outputs) != len(current_outputs):
        raise VerificationException(f"Expected {len(expected_outputs)} packets but got {len(current_outputs)}")

    # TODO should sort or something if pkts don't match, but for now we always have 1
    if len(expected_outputs) > 1:
        raise VerificationException("Sorry, haven't implemented matching for >1 packet yet")

    if len(expected_outputs) == 1:
        expected_packet = expected_outputs[0]
        actual_packet = current_outputs[0]
        for (exp_part, act_part) in zip(expected_packet, actual_packet):
            if utils.can_be_false(current_state.solver, exp_part == act_part):
                raise VerificationException(f"{act_part} may not always be {exp_part}")

    print("NF verif done! at", datetime.now())