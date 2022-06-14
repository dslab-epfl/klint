Route = {
    "length": "size_t",
    "dest": 32
}

def matches(route, ip):
    shift = 32 - route.length
    return (route.dest >> shift) == (ip >> shift)

# RFC 1812 "Requirements for IP Version 4 Routers"
def spec(packet, config, transmitted_packet):
    table = Map(Route, Device)

    if packet.device == config.devices_count - 1:
        # TODO specify the behavior here?
        return

    if (packet.ether is None) | (packet.ipv4 is None):
        assert transmitted_packet is None, "Non-Ethernet+IPv4 packets must not be forwarded"
        return

    # === §5.2.2 IP Header Validation === #

    # (1): The length reported by the link layer must be >=20 bytes
    # Ethernet guarantees >=64B packets; this is an Ethernet-only router
    # (2): The IP checksum must be correct
    # (3): The IP version number must be 4
    # (4): The IP header length must be >= 20 bytes
    # (5): The IP total length field must be large enough for the header
    if (packet.ipv4.checksum != ipv4_checksum(packet.ipv4)) | (packet.ipv4.version != 4) | (packet.ipv4.ihl < 5) | (packet.ipv4.total_length // 4 < packet.ipv4.ihl):
        assert transmitted_packet is None, "Invalid IP packets must not be forwarded"
        return


    # === §4.9.9.2 Time To Live (1) === #

    # Our router is a pure network function and cannot itself receive packets
    if packet.ipv4.time_to_live == 0:
        assert transmitted_packet is None, "Packets with a zero TTL must not be forwarded"
        return

    if transmitted_packet is not None:
        assert transmitted_packet.ipv4 is not None, "Forwarded packets must be IPv4"
        assert transmitted_packet.ipv4.time_to_live > 0, "Forwarded packets must have a nonzero TTL"

    # === §5.2.4.3 Next Hop Address === #
    if transmitted_packet is None:
        assert table.forall(lambda k, v: ~matches(k, packet.ipv4.dst)), "If the packet is not forwarded, the table must contain no matches"
    else:
        assert exists(
            Route,
            lambda r: table.__contains__(r) & # TODO: Why does 'r in table' not work here?
                      matches(r, packet.ipv4.dst) & # (1) Basic Match
                      table.forall(lambda k, v: ~matches(k, packet.ipv4.dst) | (k.length < r.length) | (v == transmitted_packet.device)) # (2) Longest Match
        ), "If the packet is forwarded, it should be matched according to LPM"
