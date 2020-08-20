import angr
import archinfo
import claripy
import executors.binary.cast as cast
import executors.binary.utils as utils
from collections import namedtuple

PACKET_MIN = 64 # the NIC will pad it if shorter
PACKET_MTU = 1512 # 1500 (Ethernet spec) + 2xMAC

# For the packet layout, see os/include/os/network.h (not reproducing here to avoid getting out of sync with changes)

# Returns packet_addr
def packet_init(state, devices_count):
  length = claripy.BVS("packet_length", 16)
  state.add_constraints(length.UGE(PACKET_MIN), length.ULE(PACKET_MTU))

  data_addr = state.memory.allocate(1, length, name="packet_data")
  device = claripy.BVS("packet_device", 16)
  state.add_constraints(device.UGE(0), device.ULT(devices_count))

  # the packet is a bit weird because of all the reserved fields, we set them to fresh symbols
  packet_addr = state.memory.allocate(1, 42, name="packet")
  state.mem[packet_addr].uint64_t = data_addr
  state.memory.store(packet_addr + 8, claripy.BVS("packet_reserved[0-3]", 14 * 8))
  state.mem[packet_addr + 22].uint16_t = device
  state.memory.store(packet_addr + 24, claripy.BVS("packet_reserved[4-6]", 16 * 8))
  state.mem[packet_addr + 40].uint16_t = length

  return packet_addr


def packet_get_data_addr(state, packet_addr):
  return state.mem[packet_addr].uint64_t.resolved

def packet_get_data(state, packet_addr):
  return state.memory.load(packet_get_data_addr(state, packet_addr), PACKET_MTU, endness=archinfo.Endness.LE)

def packet_get_device(state, packet_addr):
  return state.mem[packet_addr + 22].uint16_t.resolved

def packet_get_length(state, packet_addr):
  return state.mem[packet_addr + 40].uint16_t.resolved


NetworkMetadata = namedtuple('NetworkMetadata', ['transmitted'])

class Transmit(angr.SimProcedure):
  def run(self, packet, device, ether_header, ipv4_header, tcpudp_header):
    packet = cast.ptr(packet)
    device = cast.u16(device)
    ether_header = cast.ptr(ether_header)
    ipv4_header = cast.ptr(ipv4_header)
    tcpudp_header = cast.ptr(tcpudp_header)

    data_addr = packet_get_data_addr(self.state, packet)
    data = packet_get_data(self.state, packet)
    length = packet_get_length(self.state, packet)

    if utils.can_be_false(self.state.solver, (ether_header == 0) | (ether_header == data_addr)):
        raise "Precondition failed: ether_header is NULL or valid"

    if utils.can_be_false(self.state.solver, (ipv4_header == 0) | ((data[8*13-1:8*12] == 0x08) & (data[8*14-1:8*13] == 0x00))):
        raise "Precondition failed: ipv4_header is NULL or valid"

    if utils.can_be_false(self.state.solver, (tcpudp_header == 0) | ((tcpudp_header == 34 + data_addr) & (ipv4_header == 14 + data_addr) & ((data[8*24-1:8*23] == 6) | (data[8*24-1:8*23] == 17)))):
        raise "Precondition failed: tcpudp_header is NULL or valid"

    metadata = self.state.metadata.get(NetworkMetadata, None, default=NetworkMetadata([]))
    metadata.transmitted.append((data, length, device, ether_header != 0, ipv4_header != 0, tcpudp_header != 0))

    self.state.memory.take(100, data_addr, length)

class Flood(angr.SimProcedure):
  def run(self, packet):
    packet = cast.ptr(packet)

    data_addr = packet_get_data_addr(self.state, packet)
    data = packet_get_data(self.state, packet)
    length = packet_get_length(self.state, packet)

    metadata = self.state.metadata.get(NetworkMetadata, None, default=NetworkMetadata([]))
    metadata.transmitted.append((data, length, None, None, None, None))
