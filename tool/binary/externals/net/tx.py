import angr
import archinfo
import claripy
from collections import namedtuple

from ... import cast
from . import packet

# void net_transmit(struct net_packet* packet, device_t device, enum net_transmit_flags flags);
class net_transmit(angr.SimProcedure):
    def run(self, pkt, device, flags):
        pkt = cast.ptr(pkt)
        device = cast.uint16_t(device)
        flags = cast.enum(flags)

        data_addr = packet.get_data_addr(self.state, pkt)
        data = packet.get_data(self.state, pkt)
        length = packet.get_length(self.state, pkt)

        metadata = self.state.metadata.get_unique(packet.NetworkMetadata)
        metadata.transmitted.append((data, length, device, flags))

        self.state.memory.take(None, data_addr - packet.PACKET_MTU)

# void net_flood(struct net_packet* packet, enum net_transmit_flags flags);
class net_flood(angr.SimProcedure):
    def run(self, pkt, flags):
        pkt = cast.ptr(pkt)
        flags = cast.enum(flags)

        data_addr = packet.get_data_addr(self.state, pkt)
        data = packet.get_data(self.state, pkt)
        length = packet.get_length(self.state, pkt)

        metadata = self.state.metadata.get_unique(packet.NetworkMetadata)
        metadata.transmitted.append((data, length, None, flags))

        self.state.memory.take(None, data_addr - packet.PACKET_MTU)

# void net_flood_except(struct net_packet* packet, bool* disabled_devices, enum net_transmit_flags flags);
class net_flood_except(angr.SimProcedure):
    def run(self, pkt, disabled_devices, flags):
        pkt = cast.ptr(pkt)
        disabled_devices = cast.ptr(disabled_devices)
        flags = cast.enum(flags)

        data_addr = packet.get_data_addr(self.state, pkt)
        data = packet.get_data(self.state, pkt)
        length = packet.get_length(self.state, pkt)

        metadata = self.state.metadata.get_unique(packet.NetworkMetadata)
        metadata.transmitted.append((data, length, None, flags)) # TODO: output devices

        self.state.memory.take(None, data_addr - packet.PACKET_MTU)
