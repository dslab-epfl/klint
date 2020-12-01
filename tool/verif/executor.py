import angr
import claripy
from datetime import datetime
import inspect
import os
from pathlib import Path

from .defs import *
from .replay import *
from binary import bitsizes
from binary import utils
from binary.externals.os import config as os_config
from binary.externals.os import network as os_network
from binary.externals.os import structs as os_structs
from python import executor as py_executor


# allows e.g. "x = Expando(); x.a = 42" without predefining 'a'
class Expando:
    def __str__(self):
        return ", ".join([f"{a}: {v}" for (a, v) in inspect.getmembers(self) if "__" not in a])

    def __repr__(self):
        return str(self)


predefs_text = Path(os.path.dirname(os.path.realpath(__file__)) + "/spec_predefs.py").read_text()


def get_packet(state):
    meta = state.metadata.get_unique(os_network.NetworkMetadata)
    data = meta.received

    # For now we only add attributes if we're sure they exist or not
    # The "proper" way to do it would be to also dynamically add them if the spec constrains the path condition...oh well
    packet = Expando()
    packet.device=meta.received_device
    packet.length=meta.received_length

    # For now packets are always Ethernet so no need to check anything
    packet.ether = EthernetHeader(
        dst=data[6*8-1:0],
        src=data[12*8-1:6*8],
        type=data[14*8-1:12*8]
    )

    is_ipv4 = packet.ether.type == 0x0008 # TODO should explicitly handle endianness here (we're in LE)
    if utils.definitely_true(state.solver, is_ipv4):
        packet.ipv4 = IPv4Header(
            protocol=data[24*8-1:23*8],
            src=data[30*8-1:26*8],
            dst=data[34*8-1:30*8]
        )
        is_tcpudp = (packet.ipv4.protocol == 6) | (packet.ipv4.protocol == 17)
        if utils.definitely_true(state.solver, is_tcpudp):
            packet.tcpudp = TcpUdpHeader(
                src=data[36*8-1:34*8],
                dst=data[38*8-1:36*8]
            )
        elif utils.definitely_false(state.solver, is_tcpudp):
            packet.tcpudp = None
    elif utils.definitely_false(state.solver, is_ipv4):
        packet.ipv4 = None
        packet.tcpudp = None

    return packet

def get_config(state):
    return state.metadata.get_unique(os_config.ConfigMetadata) or os_config.ConfigMetadata([])


def get_size(size):
    if isinstance(size, str):
        return getattr(bitsizes, size)
    return size


# === Spec ptr helpers === #

def ptr_alloc(state, size):
    size = get_size(size)
    result = claripy.BVV(state.heap.malloc(size // 8), bitsizes.size_t)
    state.globals[result] = size
    return result

def ptr_read(state, ptr, size=None):
    # size is None -> we allocated it in ptr_alloc
    return state.memory.load(ptr, size or state.globals[ptr], endness=state.arch.memory_endness)


# === Spec packet helpers === #

def transmit(state, packet, device):
    pass

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
        # Very hacky: init the packet at the right time
        if "alloc" not in name:
            if 'packet_init_done' not in current_state.globals:
                os_network.packet_init(current_state, current_devices_count)
                current_state.globals['packet_init_done'] = True
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
    full_spec = predefs_text + "\n\n\n" + spec

    global current_state
    current_state = state

    global current_devices_count
    current_devices_count = devices_count

    # Add a concrete heap so we can allocate stuff outside of ghost maps, for ptr_* helpers,
    # and globals so we can store metadata about them
    state.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc())
    state.register_plugin("globals", angr.state_plugins.globals.SimStateGlobals())
    # Set up the replaying plugins
    state.symbol_factory = SymbolFactoryReplayPlugin(state.symbol_factory)
    state.memory = MemoryAllocateOpaqueReplayPlugin(state.memory)
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

    print("NF verif done! at", datetime.now())