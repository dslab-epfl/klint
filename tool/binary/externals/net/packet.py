# Standard/External libraries
import angr
import archinfo
import claripy
from collections import namedtuple

# Us
from ... import bitsizes
from ... import cast
from ... import utils

PACKET_MIN = 64 # the NIC will pad it if shorter
PACKET_MTU = 1514 # 1500 (Ethernet spec) + 2xMAC + EtherType

NetworkMetadata = namedtuple('NetworkMetadata', ['received', 'received_addr', 'received_device', 'received_length', 'transmitted'])

# For the packet layout, see os/include/net/packet.h (not reproducing here to avoid getting out of sync with changes)
PACKET_SIZE = bitsizes.ptr + bitsizes.size_t + bitsizes.uint16_t

def get_data_addr(state, packet_addr):
    return state.memory.load(packet_addr, PACKET_SIZE // 8, endness=state.arch.memory_endness)[63:0]

def get_length(state, packet_addr):
    return state.memory.load(packet_addr, PACKET_SIZE // 8, endness=state.arch.memory_endness)[127:63]

def get_device(state, packet_addr):
    return state.memory.load(packet_addr, PACKET_SIZE // 8, endness=state.arch.memory_endness)[143:128]

def get_data(state, packet_addr):
    return state.memory.load(get_data_addr(state, packet_addr), PACKET_MTU, endness=state.arch.memory_endness)

def alloc(state, devices_count):
    packet_length = claripy.BVS("packet_length", bitsizes.size_t)
    utils.add_constraints_and_check_sat(state, packet_length.UGE(PACKET_MIN), packet_length.ULE(PACKET_MTU))
    # Allocate 2*MTU so that BPF's adjust_head can adjust negatively
    # TODO instead, memcpy should be an intrinsic, and then adjust_head can memcpy into an init-allocated buffer
    data_addr = state.memory.allocate(1, 2 * PACKET_MTU, name="packet_data") # TODO: allocate with packet_length size instead; find another way to deal with BPF
    packet_device = claripy.BVS("packet_device", bitsizes.uint16_t)
    utils.add_constraints_and_check_sat(state, packet_device.ULT(devices_count))
    # Ignore the _padding and os_tag, we just pretend they don't exist so that code cannot possibly access them
    packet_addr = state.memory.allocate(1, PACKET_SIZE // 8, name="packet")
    packet_data = packet_device.concat(packet_length).concat(data_addr + PACKET_MTU)
    state.memory.store(packet_addr, packet_data, endness=state.arch.memory_endness)
    # attach to packet_addr just because we need something to attach to... TODO it'd be nice to have statewide metadata
    state.metadata.set(packet_addr, NetworkMetadata(get_data(state, packet_addr), data_addr, packet_device, packet_length, []))
    return packet_addr
