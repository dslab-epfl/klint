import angr
from angr.sim_type import *
import archinfo
import claripy
from collections import namedtuple

from . import packet

TransmissionMetadata = namedtuple("TransmissionMetadata", ["data_addr", "length", "flags", "is_flood", "device", "excluded_devices"])

# void net_transmit(struct net_packet* packet, device_t device, enum net_transmit_flags flags);
class net_transmit(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypeNum(16, False), SimTypeInt(True)], None, arg_names=["packet", "device", "flags"])

    def run(self, pkt, device, flags):
        data_addr = packet.get_data_addr(self.state, pkt)
        length = packet.get_length(self.state, pkt)

        metadata = self.state.metadata.get_one(packet.NetworkMetadata)
        metadata.transmitted.append(TransmissionMetadata(data_addr, length, flags, False, device, None))

# void net_flood(struct net_packet* packet, enum net_transmit_flags flags);
class net_flood(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypeInt(True)], None, arg_names=["packet", "flags"])

    def run(self, pkt, flags):
        data_addr = packet.get_data_addr(self.state, pkt)
        length = packet.get_length(self.state, pkt)
        device = packet.get_device(self.state, pkt)

        metadata = self.state.metadata.get_one(packet.NetworkMetadata)
        metadata.transmitted.append(TransmissionMetadata(data_addr, length, flags, True, device, None))

# void net_flood_except(struct net_packet* packet, bool* disabled_devices, enum net_transmit_flags flags);
class net_flood_except(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void")), SimTypePointer(SimTypeBool), SimTypeInt(True)], None, arg_names=["packet", "disabled_devices", "flags"])

    def run(self, pkt, disabled_devices, flags):
        data_addr = packet.get_data_addr(self.state, pkt)
        length = packet.get_length(self.state, pkt)
        device = packet.get_device(self.state, pkt)

        metadata = self.state.metadata.get_one(packet.NetworkMetadata)
        metadata.transmitted.append(TransmissionMetadata(data_addr, length, flags, True, device, disabled_devices))
