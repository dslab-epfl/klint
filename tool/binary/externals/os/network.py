# Standard/External libraries
import angr
import archinfo
import claripy
from collections import namedtuple

# Us
from ... import cast
from ... import utils
from ...exceptions import SymbexException

PACKET_MIN = 64 # the NIC will pad it if shorter
PACKET_MTU = 1514 # 1500 (Ethernet spec) + 2xMAC + EtherType

NetworkMetadata = namedtuple('NetworkMetadata', ['received', 'received_device', 'received_length', 'transmitted'])

# For the packet layout, see os/include/os/network.h (not reproducing here to avoid getting out of sync with changes)

def packet_get_data_addr(state, packet_addr):
    return state.mem[packet_addr].uint64_t.resolved

def packet_get_data(state, packet_addr):
    return state.memory.load(packet_get_data_addr(state, packet_addr), PACKET_MTU, endness=archinfo.Endness.LE)

def packet_get_device(state, packet_addr):
    return state.mem[packet_addr + 22].uint16_t.resolved

def packet_get_length(state, packet_addr):
    return state.mem[packet_addr + 40].uint16_t.resolved

# Pre-initialize so replays go smoothly
packet_length = claripy.BVS("packet_length", 16)
packet_device = claripy.BVS("packet_device", 16)
packet_reserved_0 = claripy.BVS("packet_reserved[0-3]", 14 * 8)
packet_reserved_1 = claripy.BVS("packet_reserved[4-6]", 16 * 8)

# Returns packet_addr
def packet_init(state, devices_count):
    state.add_constraints(packet_length.UGE(PACKET_MIN), packet_length.ULE(PACKET_MTU))

    # Allocate 2*MTU so that BPF's adjust_head can adjust negatively
    # TODO instead, memcpy should be an intrinsic, and then adjust_head can memcpy into an init-allocated buffer
    data_addr = state.memory.allocate(1, 2 * PACKET_MTU, name="packet_data")
    state.add_constraints(packet_device.ULT(devices_count))

    # the packet is a bit weird because of all the reserved fields, we set them to fresh symbols
    packet_addr = state.memory.allocate(1, 42, name="packet")
    state.mem[packet_addr].uint64_t = data_addr + PACKET_MTU
    state.memory.store(packet_addr + 8, packet_reserved_0)
    state.mem[packet_addr + 22].uint16_t = packet_device
    state.memory.store(packet_addr + 24, packet_reserved_1)
    state.mem[packet_addr + 40].uint16_t = packet_length

    # attach to packet_addr just because we need something to attach to... TODO it'd be nice to have statewide metadata
    state.metadata.set(packet_addr, NetworkMetadata(packet_get_data(state, packet_addr), packet_device, packet_length, []))

    return packet_addr


class Transmit(angr.SimProcedure):
    def run(self, packet, device, ether_header, ipv4_header, tcpudp_header):
        packet = cast.ptr(packet)
        device = cast.uint16_t(device)
        ether_header = cast.ptr(ether_header)
        ipv4_header = cast.ptr(ipv4_header)
        tcpudp_header = cast.ptr(tcpudp_header)

        data_addr = packet_get_data_addr(self.state, packet)
        data = packet_get_data(self.state, packet)
        length = packet_get_length(self.state, packet)

        if utils.can_be_false(self.state.solver, (ether_header == 0) | (ether_header == data_addr)):
            raise SymbexException("Precondition failed: ether_header is NULL or valid")

        if utils.can_be_false(self.state.solver, (ipv4_header == 0) | ((data[8*13-1:8*12] == 0x08) & (data[8*14-1:8*13] == 0x00))):
           raise SymbexException("Precondition failed: ipv4_header is NULL or valid")

        if utils.can_be_false(self.state.solver, (tcpudp_header == 0) | ((tcpudp_header == 34 + data_addr) & (ipv4_header == 14 + data_addr) & ((data[8*24-1:8*23] == 6) | (data[8*24-1:8*23] == 17)))):
            raise SymbexException("Precondition failed: tcpudp_header is NULL or valid")

        metadata = self.state.metadata.get_unique(NetworkMetadata)
        metadata.transmitted.append((data, length, device, ether_header != 0, ipv4_header != 0, tcpudp_header != 0))

        self.state.memory.take(None, data_addr, None)

class Flood(angr.SimProcedure):
    def run(self, packet):
        packet = cast.ptr(packet)

        _ = packet_get_data_addr(self.state, packet)
        data = packet_get_data(self.state, packet)
        length = packet_get_length(self.state, packet)

        metadata = self.state.metadata.get_unique(NetworkMetadata)
        metadata.transmitted.append((data, length, None, None, None, None))
