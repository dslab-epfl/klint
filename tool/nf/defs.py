# Standard/External libraries
from collections import namedtuple

EthernetHeader = namedtuple(
    "EthernetHeader", [
        "src_addr",
        "dst_addr",
        "type"
    ]
)

IPv4Header = namedtuple(
    "Ipv4Header", [
        # TODO other fields - don't care for now
        "protocol",
        "src_addr",
        "dst_addr"
    ]
)

TcpUdpHeader = namedtuple(
    "TcpUdpHeader", [
        "src_port",
        "dst_port"
    ]
)

ReceivedPacket = namedtuple(
    "ReceivedPacket", [
        "device", # unsigned integer, less than 2**16
        "data", # array of bytes, i.e. unsigned integers less than 2**8
        "length" # unsigned integer, currently limited to the Ethernet MTU of 1512 bytes
    ]
)

SentPacket = namedtuple(
    "SentPacket", [
        "device", # unsigned integer, less than 2**16
        "data", # array of bytes, i.e. unsigned integers less than 2**8
        "length", # unsigned integer, currently limited to the Ethernet MTU of 1512 bytes
        "updated_ethernet_addresses", # Boolean, True if the packet should be considered to have up-to-date Ethernet addresses
        "updated_ip_checksum", # Boolean, True if the packet should be considered to have an up-to-date IP checksum
        "updated_udptcp_checksum" # Boolean, True if the packet should be considered to have an up-to-date UDP or TCP checksum
    ]
)

NFInput = namedtuple(
    "NFInput", [
        "packet", # ReceivedPacket
        "state_metadata", # angr state metadata items
        "config" # dictionary containing configuration values, keyed by their name
    ]
)

NFOutput = namedtuple(
    "NFResult", [
        "packets", # list of SentPacket
        "state", # angr state
    ]
)
