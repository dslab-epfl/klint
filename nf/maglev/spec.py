Flow = {
    'src_ip': 32,
    'dst_ip': 32,
    'src_port': 16,
    'dst_port': 16,
    'protocol': 8
}

def spec(packet, config, transmitted_packet):
    if (packet.ipv4 is None) | (packet.tcpudp is None):
        assert transmitted_packet is None
        return

    flows = ExpiringSet(Flow, config["flow expiration time"], config["flow capacity"], packet.time)
    backends = Map(Device, Time)
    flows_to_backends = Map("size_t", Device)

    if packet.device == config.devices_count - 1:
        flow = {
            'src_ip': packet.ipv4.src,
            'dst_ip': packet.ipv4.dst,
            'src_port': packet.tcpudp.src,
            'dst_port': packet.tcpudp.dst,
            'protocol': packet.ipv4.protocol
        }

        if transmitted_packet is None:
            assert backends.forall(lambda k, v: (k < 0) | (k >= config.devices_count - 1))
        else:
            if flow not in flows:
                assert flows.old.full
            # TODO assert device; but we need the CHT info for that... uninterpreted functions maybe?
            assert transmitted_packet.data == packet.data
    else:
        assert packet.device in backends
        assert backends[packet.device] == packet.time
