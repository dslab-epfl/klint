import inspect

from .defs import *
from binary import utils
from binary.externals.os import config as os_config # the metadata decl should probably not be in there; oh well
from binary.externals.os import network as os_network # the metadata decl should probably not be in there; oh well

# allows e.g. "x = Expando(); x.a = 42" without predefining 'a'
class Expando:
    def __str__(self):
        return ", ".join([f"{a}: {v}" for (a, v) in inspect.getmembers(self) if "__" not in a])

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

def verify(state, devices_count, spec): # TODO why do we have to move the devices_count around like that? :/
    print(get_packet(state))
    print(get_config(state))
    print()