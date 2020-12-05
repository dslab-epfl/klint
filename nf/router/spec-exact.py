def spec(packet, config, devices_count):
    table = LongestPrefixMatch()

    if packet.ether is None or packet.ipv4 is None:
        return

    destination = table.lookup(packet.ipv4.dst)
    if destination is not None:
        transmit(packet, destination)
