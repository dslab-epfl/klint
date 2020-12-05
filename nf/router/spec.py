Route = {
    "dest": "uint32_t",
    "length": "uint8_t"
}
Device = "uint16_t"

def matches(route, ip):
    return (route.dest >> route.length) == (ip >> route.length)

def spec(packet, config):
    table = Map(Route, Device)

    # === §5.2.2 IP Header Validation === #

    # (1): The length reported by the link layer must be >=20 bytes
    # Ethernet guarantees >=64B packets; this is an Ethernet-only router
    if packet.ether is None:
        return

    # Ensure the packet is actually IP
    if packet.ipv4 is None:
        return

    # (2): The IP checksum must be correct
    # TODO add an ip checksum feature (just return a symbol and put it in the metadata as "the checksum of...")
    #if packet.ipv4.checksum != ipv4_checksum(packet.ipv4):
    #    return

    # (3): The IP version number must be 4
    if packet.ipv4.version != 4:
        return

    # (4): The IP header length must be >= 20 bytes
    if packet.ipv4.ihl*4 < 20:
        return

    # (5): The IP total length field must be large enough for the header
    if packet.ipv4.total_length < packet.ipv4.ihl*4:
        return

    # === §4.9.9.2 Time To Live === #

    # Our router is a pure network function and cannot itself receive packets
    if packet.ipv4 is None or packet.ipv4.time_to_live == 0:
        return

    transmitted_packet = get_transmitted_packet()

    assert transmitted_packet.ipv4 is not None
    assert transmitted_packet.ipv4.time_to_live > 0


    # === §5.2.4.3 Next Hop Address === #

    dst_ip = transmitted_packet.ipv4.dst
    dst_device = transmitted_packet.device

    assert exists(
        Route,
        lambda r: dst_device == table.get(r) and
                  matches(dst_route, dst_ip) and
                  table.forall(lambda k, v: implies(matches(k, dst_ip), k.length <= r.length))
    )