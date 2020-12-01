import claripy
from datetime import datetime
import inspect
import os
from pathlib import Path

from .defs import *
from .memory_simple import SimpleMemory
from .replay import *
from binary import bitsizes
from binary import utils
from binary.externals.os import config as os_config
from binary.externals.os import network as os_network
from binary.externals.os import structs as os_structs
from binary.ghost_maps import *
from python import executor as py_executor

class VerificationException(Exception): pass

class SpecPacket:
    def __init__(self, state, data_addr, data, length, device):
        self._state = state
        self._data_addr = data_addr
        self.data = data
        self.length = length
        self.device = device

    @property
    def ether(self):
        return EthernetHeader(
            dst=self.data[6*8-1:0],
            src=self.data[12*8-1:6*8],
            type=self.data[14*8-1:12*8]
        )

    @property
    def ipv4(self):
        if self.ether is None:
            return None
        is_ipv4 = self.ether.type == 0x0008 # TODO should explicitly handle endianness here (we're in LE)
        if utils.definitely_true(self._state.solver, is_ipv4):
            return IPv4Header(
                protocol=self.data[24*8-1:23*8],
                src=self.data[30*8-1:26*8],
                dst=self.data[34*8-1:30*8]
            )
        elif utils.definitely_false(self._state.solver, is_ipv4):
            return None
        raise VerificationException("May or may not be IPv4; this case isn't handled yet")

    @property
    def tcpudp(self):
        if self.ipv4 is None:
            return None
        is_tcpudp = (self.ipv4.protocol == 6) | (self.ipv4.protocol == 17)
        if utils.definitely_true(self._state.solver, is_tcpudp):
            return TcpUdpHeader(
                src=self.data[36*8-1:34*8],
                dst=self.data[38*8-1:36*8]
            )
        elif utils.definitely_false(self._state.solver, is_tcpudp):
            return None
        raise VerificationException("May or may not be TCP/UDP; this case isn't handled yet")


def init_network_if_needed(state):
    if current_state.metadata.get_unique(os_network.NetworkMetadata) is None:
        os_network.packet_init(current_state, current_devices_count)

def get_packet(state):
    meta = state.metadata.get_unique(os_network.NetworkMetadata)
    data = meta.received
    return SpecPacket(state, meta.received_addr, data, meta.received_length, meta.received_device)

def get_config(state):
    return state.metadata.get_unique(os_config.ConfigMetadata) or os_config.ConfigMetadata([])

def get_outputs(state):
    return state.metadata.get_unique(os_network.NetworkMetadata).transmitted

def get_size(size):
    if isinstance(size, str):
        return getattr(bitsizes, size)
    return size


# === Spec ptr helpers === #

def ptr_alloc(state, size):
    size = get_size(size)
    return state.memory.allocate_stack(size)

def ptr_read(state, ptr, size=None):
    if size is not None:
        size = get_size(size) // 8
    # size is None -> we allocated it in ptr_alloc
    return state.memory.load(ptr, size, endness=state.arch.memory_endness)


# === Spec packet helpers === #

def transmit(state, packet, device):
    global current_state
    global current_outputs
    current_outputs.append((packet.data, packet.length, device))
    current_state.memory.take(None, packet._data_addr, None) # mimic what the real transmit does

externals = {
    # Spec helpers
    "ptr_alloc": ptr_alloc,
    "ptr_read": ptr_read,
    "transmit": transmit,
    # Contracts
    "lpm_alloc": os_structs.lpm.LpmAlloc,
    "lpm_lookup_elem": os_structs.lpm.LpmLookupElem
}

def handle_externals(name, py_state, *args, **kwargs):
    global current_state
    global current_devices_count

    ext = externals[name]
    if inspect.isclass(ext): # it's a SimProcedure
        # HACK: init the packet at the right time
        if "alloc" not in name:
            init_network_if_needed(current_state)
        ext_inst = ext()
        ext_inst.state = current_state
        result = ext_inst.run(*args)
        if result.size() == bitsizes.bool and not result.symbolic:
            return not result.structurally_match(claripy.BVV(0, bitsizes.bool))
        return result
    else:
        return ext(current_state, *args)


def verify(state, devices_count, spec): # TODO why do we have to move the devices_count around like that? :/
    packet = get_packet(state)
    config = get_config(state)
    expected_outputs = get_outputs(state)

    if 'predefs_text' not in globals():
        global predefs_text
        predefs_text = Path(os.path.dirname(os.path.realpath(__file__)) + "/spec_predefs.py").read_text()

    full_spec = predefs_text + "\n\n\n" + spec

    global current_state
    current_state = state

    global current_devices_count
    current_devices_count = devices_count

    global current_outputs
    current_outputs = []

    # Set up the replaying plugins
    state.symbol_factory = SymbolFactoryReplayPlugin(state.symbol_factory)
    state.memory = SimpleMemory(MemoryAllocateOpaqueReplayPlugin(state.memory.abstract_memory)) # extract the abstract one to ensure we do not need the concrete one
    state.maps = GhostMapReplayPlugin(state)
    # Remove metadata, since replaying will add it back
    state.metadata.clear()

    py_executor.execute(
        solver=state.solver,
        spec_text=full_spec,
        spec_fun_name="spec",
        spec_args=[packet, config, devices_count],
        spec_external_names=externals.keys(),
        spec_external_handler=handle_externals
    )

    # in case it wasn't done during the execution (see HACK above)
    init_network_if_needed(current_state)

    current_state.path.ghost_free([RecordGet])
    if len(current_state.path.ghost_get_remaining()):
        raise VerificationException(f"There are operations remaining: {current_state.path.ghost_get_remaining()}")

    if len(expected_outputs) != len(current_outputs):
        raise VerificationException(f"Expected {len(expected_outputs)} packets but got {len(current_outputs)}")

    # TODO should sort or something if pkts don't match, but for now we always have 1
    if len(expected_outputs) > 1:
        raise VerificationException("Sorry, haven't implemented matching for >1 packet yet")

    if len(expected_outputs) == 1:
        expected_packet = expected_outputs[0]
        actual_packet = current_outputs[0]
        for (exp_part, act_part) in zip(expected_packet, actual_packet):
            if utils.can_be_false(state.solver, exp_part == act_part):
                raise VerificationException(f"{act_part} may not always be {exp_part}")

    print("NF verif done! at", datetime.now())