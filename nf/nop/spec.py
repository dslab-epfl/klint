def spec(packet, config, state, sent_packets):
    if packet.device == config['wan device']:
        dst_device = config['lan device']
    else:
        dst_device = config['wan device']

    assert sent_packets == [(packet, dst_device, TransmitFlags.UPDATE_ETHERNET_ADDRESSES)]
