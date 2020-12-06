def spec(packet, config, transmitted_packet):
    # The policer is at a network boundary and should thus reject non-IP packets
    if packet.ipv4 is None:
        assert transmitted_packet is None
        return

    # Only packets from the WAN device should be policed
    if packet.device != config["wan device"]:
        assert transmitted_packet is not None