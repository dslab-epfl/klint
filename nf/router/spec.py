Route = {
    "length": "uint8_t",
    "dest": "uint32_t"
}
Device = "uint16_t"

def matches(route, ip):
    return (route.dest >> route.length) == (ip >> route.length)

def spec(packet, config, transmitted_packet):
    table = Map(Route, Device)

    # === §5.2.2 IP Header Validation === #

    # (1): The length reported by the link layer must be >=20 bytes
        # Ethernet guarantees >=64B packets; this is an Ethernet-only router
    if (packet.ether is None or
         # Ensure the packet is actually IP
         packet.ipv4 is None or
         # (2): The IP checksum must be correct
         packet.ipv4.checksum != ipv4_checksum(packet.ipv4) or
         # (3): The IP version number must be 4
         packet.ipv4.version != 4 or
         # (4): The IP header length must be >= 20 bytes
         packet.ipv4.ihl*4 < 20 or
         # (5): The IP total length field must be large enough for the header
         packet.ipv4.total_length < packet.ipv4.ihl*4):
        assert transmitted_packet is None
        return


    # === §4.9.9.2 Time To Live (1) === #

    # Our router is a pure network function and cannot itself receive packets
    if packet.ipv4.time_to_live == 0:
        assert transmitted_packet is None
        return

    if transmitted_packet is not None:
        assert transmitted_packet.ipv4 is not None
        assert transmitted_packet.ipv4.time_to_live > 0


    # === §5.2.4.3 Next Hop Address === #
    if transmitted_packet is None:
        assert table.forall(lambda k, v: ~matches(k, packet.ipv4.dst))
    else:
        assert exists(
            Route,
            lambda r: matches(r, packet.ipv4.dst) & # (1) Basic Match
                      table.forall(lambda k, v: ~matches(k, packet.ipv4.dst) | (k.length < r.length) | (v == transmitted_packet.device)) # (2) Longest Match
        )