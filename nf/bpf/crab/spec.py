def spec(packet, config, transmitted_packet):
    if transmitted_packet is not None:
        assert packet.ipv4 is not None
        assert packet.ipv4.ihl >= 5
