Route = {
    "dest": "uint32_t",
    "length": "uint8_t"
}
Device = "uint16_t"

def matches(route, ip):
    return (route.dest >> route.length) == (ip >> route.length)

def spec(packet, config, transmitted_packet):
    table = Map(Route, Device)

    # === §5.2.2 IP Header Validation === #

    # (1): The length reported by the link layer must be >=20 bytes
    # Ethernet guarantees >=64B packets; this is an Ethernet-only router
    if packet.ether is None:
        return transmitted_packet is None

    # Ensure the packet is actually IP
    if packet.ipv4 is None:
        return transmitted_packet is None

    # (2): The IP checksum must be correct
    # TODO add an ip checksum feature (just return a symbol and put it in the metadata as "the checksum of...")
    #if packet.ipv4.checksum != ipv4_checksum(packet.ipv4):
    #    return

    # (3): The IP version number must be 4
    if packet.ipv4.version != 4:
        return transmitted_packet is None

    # (4): The IP header length must be >= 20 bytes
    if packet.ipv4.ihl*4 < 20:
        return transmitted_packet is None

    # (5): The IP total length field must be large enough for the header
    if packet.ipv4.total_length < packet.ipv4.ihl*4:
        return transmitted_packet is None


    # === §4.9.9.2 Time To Live (1) === #

    # Our router is a pure network function and cannot itself receive packets
    if packet.ipv4.time_to_live == 0:
        return transmitted_packet is None

    if transmitted_packet is not None:
        assert transmitted_packet.ipv4 is not None
        assert transmitted_packet.ipv4.time_to_live > 0


    # === §5.2.4.3 Next Hop Address === #
    if transmitted_packet is None:
        assert table.forall(lambda k, v: ~matches(k, packet.ipv4.dst))
    else:
        assert exists(
            Route,
            lambda r: transmitted_packet.device == table.get(r) &
                      matches(dst_route, packet.ipv4.dst) &
                      table.forall(lambda k, v: ~matches(k, packet.ipv4.dst) | (k.length <= r.length))
        )