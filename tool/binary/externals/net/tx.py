# Standard/External libraries
import angr
import archinfo
import claripy
from collections import namedtuple

# Us
from ... import cast
from . import packet

# void net_transmit(struct net_packet* packet, device_t device, enum net_transmit_flags flags);
class net_transmit(angr.SimProcedure):
    def run(self, pkt, device, flags):
        pkt = cast.ptr(pkt)
        device = cast.uint16_t(device)
        flags = cast.enum(device)

        data_addr = packet.get_data_addr(self.state, pkt)
        data = packet.get_data(self.state, pkt)
        length = packet.get_length(self.state, pkt)

        metadata = self.state.metadata.get_unique(packet.NetworkMetadata)
        metadata.transmitted.append((data, length, device, flags))

        self.state.memory.take(None, data_addr)

# void net_flood(struct net_packet* packet);
class net_flood(angr.SimProcedure):
    def run(self, pkt):
        pkt = cast.ptr(pkt)

        data_addr = packet.get_data_addr(self.state, pkt)
        data = packet.get_data(self.state, pkt)
        length = packet.get_length(self.state, pkt)

        metadata = self.state.metadata.get_unique(packet.NetworkMetadata)
        metadata.transmitted.append((data, length, None, None))

        self.state.memory.take(None, data_addr)
