def spec(packet, config, transmitted_packet):
    # The policer is at a network boundary and should thus reject non-IP packets
    if packet.ipv4 is None:
        assert transmitted_packet is None
        return

    # Only packets from the WAN device should be policed
    if packet.device != config["wan device"]:
        assert transmitted_packet is not None
        return

    # New flows cannot begin with an overly large packet since they'd already exceed their budget
    table = Map(typeof(packet.ipv4.dst), ...)
    if ~table.has(packet.ipv4.dst) & (packet.length > config["burst"]):
        assert transmitted_packet is None