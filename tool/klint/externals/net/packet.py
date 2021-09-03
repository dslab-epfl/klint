import angr
import claripy
from collections import namedtuple

from kalm import clock
from kalm import utils

PACKET_MIN = 60 # the NIC will pad it if shorter
PACKET_MTU = 1514 # 1500 (Ethernet spec) + 2xMAC + EtherType

NetworkMetadata = namedtuple('NetworkMetadata', ['received_addr', 'received_device', 'received_length', 'transmitted'])

# For the packet layout, see the C header (not reproducing here to avoid getting out of sync with changes)
def packet_size(state):
    return state.sizes.ptr + state.sizes.size_t + state.sizes.uint64_t + state.sizes.uint16_t

def get_data_addr(state, packet_addr):
    return state.memory.load(packet_addr, state.sizes.ptr // 8, endness=state.arch.memory_endness)

def get_length(state, packet_addr):
    return state.memory.load(packet_addr+(state.sizes.ptr // 8), state.sizes.size_t // 8, endness=state.arch.memory_endness)

def get_device(state, packet_addr):
    return state.memory.load(packet_addr+((state.sizes.uint64_t+state.sizes.size_t+state.sizes.ptr) // 8), state.sizes.uint16_t // 8, endness=state.arch.memory_endness)

def alloc(state, devices_count):
    # Ignore the _padding and os_tag, we just pretend they don't exist so that code cannot possibly access them
    packet_addr = state.heap.allocate(1, packet_size(state) // 8, name="packet")
    packet_length = claripy.BVS("packet_length", state.sizes.size_t)
    state.solver.add(packet_length.UGE(PACKET_MIN), packet_length.ULE(PACKET_MTU))
    data_addr = state.heap.allocate(packet_length, 1, ephemeral=True, name="packet_data")
    packet_device = claripy.BVS("packet_device", state.sizes.uint16_t)
    state.solver.add(packet_device.ULT(devices_count))
    (packet_time, _) = clock.get_time_and_cycles(state)
    packet_data = packet_device.concat(packet_time).concat(packet_length).concat(data_addr)
    state.memory.store(packet_addr, packet_data, endness=state.arch.memory_endness)
    state.metadata.append(None, NetworkMetadata(data_addr, packet_device, packet_length, []))
    return packet_addr
