# Standard/External libraries
import angr
import archinfo
import claripy
from collections import namedtuple

# Us
from ... import bitsizes
from ... import cast
from ... import utils
from ...exceptions import SymbexException

PACKET_MIN = 64 # the NIC will pad it if shorter
PACKET_MTU = 1514 # 1500 (Ethernet spec) + 2xMAC + EtherType

NetworkMetadata = namedtuple('NetworkMetadata', ['received', 'received_addr', 'received_device', 'received_length', 'transmitted'])

# For the packet layout, see os/include/net/packet.h (not reproducing here to avoid getting out of sync with changes)
def get_data_addr(state, packet_addr):
    return state.memory.load(packet_addr, bitsizes.size_t // 8, endness=state.arch.memory_endness)

def get_data(state, packet_addr):
    return state.memory.load(get_data_addr(state, packet_addr), PACKET_MTU , endness=state.arch.memory_endness)

def get_length(state, packet_addr):
    return state.memory.load(packet_addr + bitsizes.ptr, bitsizes.size_t // 8, endness=state.arch.memory_endness)

def get_device(state, packet_addr):
    return state.memory.load(packet_addr + bitsizes.ptr + bitsizes.size_t, bitsizes.uint16_t // 8, endness=state.arch.memory_endness)

def alloc(state, devices_count):
    packet_length = state.symbol_factory.BVS("packet_length", bitsizes.size_t)
    state.add_constraints(packet_length.UGE(PACKET_MIN), packet_length.ULE(PACKET_MTU))
    # Allocate 2*MTU so that BPF's adjust_head can adjust negatively
    # TODO instead, memcpy should be an intrinsic, and then adjust_head can memcpy into an init-allocated buffer
    data_addr = state.memory.allocate(1, 2 * PACKET_MTU, name="packet_data")
    packet_device = state.symbol_factory.BVS("packet_device", bitsizes.uint16_t)
    state.add_constraints(packet_device.ULT(devices_count))
    # Ignore the _padding and os_tag, we just pretend they don't exist so that code cannot possibly access them
    packet_addr = state.memory.allocate(1, bitsizes.ptr + 2 * bitsizes.uint16_t, name="packet")
    state.memory.store(packet_addr, data_addr + PACKET_MTU, endness=state.arch.memory_endness)
    state.memory.store(packet_addr + bitsizes.ptr, packet_length, endness=state.arch.memory_endness)
    state.memory.store(packet_addr + bitsizes.ptr + bitsizes.size_t, packet_device, endness=state.arch.memory_endness)
    # attach to packet_addr just because we need something to attach to... TODO it'd be nice to have statewide metadata
    state.metadata.set(packet_addr, NetworkMetadata(get_data(state, packet_addr), data_addr, packet_device, packet_length, []))
    return packet_addr
