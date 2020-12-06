# Standard/External libraries
from collections import namedtuple

EthernetHeader = namedtuple(
    "EthernetHeader", [
        "dst",
        "src",
        "type"
    ]
)

IPv4Header = namedtuple(
    "Ipv4Header", [
        # TODO other fields - don't care for now
        "version",
        "ihl",
        "total_length",
        "time_to_live",
        "protocol",
        "checksum",
        "src",
        "dst"
    ]
)

TcpUdpHeader = namedtuple(
    "TcpUdpHeader", [
        "src",
        "dst"
    ]
)