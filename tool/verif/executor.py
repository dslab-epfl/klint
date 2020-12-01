from angr.state_plugins.solver import SimSolver
from archinfo.arch_amd64 import ArchAMD64
import claripy
from collections import namedtuple
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
from binary.memory_fractional import FractionalMemory
from binary.metadata import MetadataPlugin
from binary.path import PathPlugin
from python import executor as py_executor

class VerificationException(Exception): pass

class SpecPacket:
    def __init__(self, state, network_meta):
        self._state = state
        self._data_addr = network_meta.received_addr
        self.data = network_meta.received
        self.length = network_meta.received_length
        self.device = network_meta.received_device

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




# === Spec type helpers === #

def type_size(size):
    if isinstance(size, str):
        return getattr(bitsizes, size)
    return size

# === Spec ptr helpers === #

def ptr_alloc(state, size):
    size = type_size(size)
    return state.memory.allocate_stack(size)

def ptr_read(state, ptr, size=None):
    if size is not None:
        size = type_size(size) // 8
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
    "type_size": type_size,
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

class SpecState: pass

def verify(data, spec): 
    if 'predefs_text' not in globals():
        global predefs_text
        predefs_text = Path(os.path.dirname(os.path.realpath(__file__)) + "/spec_predefs.py").read_text()
    full_spec = predefs_text + "\n\n\n" + spec

    global current_state
    current_state = SpecState()
    current_state.maps = GhostMapsReplayPlugin(current_state)
    current_state.metadata = MetadataPlugin()
    current_state.path = PathPlugin([], data.ghost_history)
    current_state.symbol_factory =  SymbolFactoryReplayPlugin(data.symbol_history)

    # Angr plugins make some assumptions about structure
    current_state._get_weakref = lambda: current_state # not really a weakref; whatever
    current_state._global_condition = None
    current_state.arch = ArchAMD64()
    current_state.options = angr.options.symbolic
    current_state.supports_inspect = False

    current_state.memory = FractionalMemory(memory_id="mem")
    current_state.memory.set_state(current_state)
    current_state.memory = SimpleMemory(MemoryAllocateOpaqueReplayPlugin(current_state.memory))

    current_state.solver = SimSolver()
    current_state.solver.set_state(current_state)
    current_state.solver.add(*data.constraints)

    # Common shortcuts we use
    current_state.add_constraints = current_state.solver.add
    current_state.satisfiable = current_state.solver.satisfiable

    global current_devices_count
    current_devices_count = data.devices_count

    global current_outputs
    current_outputs = []

    packet = SpecPacket(current_state, data.network)

    py_executor.execute(
        solver=current_state.solver,
        spec_text=full_spec,
        spec_fun_name="spec",
        spec_args=[packet, data.config, data.devices_count],
        spec_external_names=externals.keys(),
        spec_external_handler=handle_externals
    )

    # in case it wasn't done during the execution (see HACK above)
    init_network_if_needed(current_state)

    current_state.path.ghost_free([RecordGet])
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