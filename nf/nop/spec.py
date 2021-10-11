def spec(packet, config, transmitted_packet):
    if packet.device == config['wan device']:
        assert transmitted_packet.device == config['lan device']
    else:
        assert transmitted_packet.device == config['wan device']

#    assert transmitted_packet.data[:96] == packet.data[:96] # ignore MACs for now
