import angr
import archinfo
import claripy
from collections import namedtuple

from . import packet

TransmissionMetadata = namedtuple("TransmissionMetadata", ["data", "length", "flags", "is_flood", "device", "excluded_devices"])

# TODO enforce model where it's the "right" buffer we're sending and enforce the NF doesn't touch it afterwards

# void net_transmit(struct net_packet* packet, device_t device, enum net_transmit_flags flags);
class net_transmit(angr.SimProcedure):
    def run(self, pkt, device, flags):
        pkt = self.state.casts.ptr(pkt)
        device = self.state.casts.uint16_t(device)
        flags = self.state.casts.enum(flags)

        data_addr = packet.get_data_addr(self.state, pkt)
        data = packet.get_data(self.state, pkt)
        length = packet.get_length(self.state, pkt)

        metadata = self.state.metadata.get_one(packet.NetworkMetadata)
        metadata.transmitted.append(TransmissionMetadata(data, length, flags, False, device, None))

        #self.state.memory.take(None, data_addr - packet.PACKET_MTU)

# void net_flood(struct net_packet* packet, enum net_transmit_flags flags);
class net_flood(angr.SimProcedure):
    def run(self, pkt, flags):
        pkt = self.state.casts.ptr(pkt)
        flags = self.state.casts.enum(flags)

        data_addr = packet.get_data_addr(self.state, pkt)
        data = packet.get_data(self.state, pkt)
        length = packet.get_length(self.state, pkt)
        device = packet.get_device(self.state, pkt)

        metadata = self.state.metadata.get_one(packet.NetworkMetadata)
        metadata.transmitted.append(TransmissionMetadata(data, length, flags, True, device, None))

        #self.state.memory.take(None, data_addr - packet.PACKET_MTU)

# void net_flood_except(struct net_packet* packet, bool* disabled_devices, enum net_transmit_flags flags);
class net_flood_except(angr.SimProcedure):
    def run(self, pkt, disabled_devices, flags):
        pkt = self.state.casts.ptr(pkt)
        disabled_devices = self.state.casts.ptr(disabled_devices)
        flags = self.state.casts.enum(flags)

        data_addr = packet.get_data_addr(self.state, pkt)
        data = packet.get_data(self.state, pkt)
        length = packet.get_length(self.state, pkt)
        device = packet.get_device(self.state, pkt)

        metadata = self.state.metadata.get_one(packet.NetworkMetadata)
        metadata.transmitted.append(TransmissionMetadata(data, length, flags, True, device, disabled_devices))

        #self.state.memory.take(None, data_addr - packet.PACKET_MTU)
