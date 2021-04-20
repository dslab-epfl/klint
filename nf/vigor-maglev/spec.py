Backend = {
    'ip': 32,
    'device': Device,
}

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

    flows = ExpiringSet(Flow, config["flow expiration time"], config["flow capacity"])
    backends = ExpiringSet(Backend, config["backend expiration time"], config["backend capacity"])

    if packet.device == config["wan device"]:
        flow = {
            'src_ip': packet.ipv4.src,
            'dst_ip': packet.ipv4.dst,
            'src_port': packet.tcpudp.src,
            'dst_port': packet.tcpudp.dst,
            'protocol': packet.ipv4.protocol
        }

        if flow not in flows:
            assert flows.old.full
            assert transmitted_packet is None
            return

        backend_index = flows.get_index(flow)
        backend = backends.get_by_index(backend_index)
        assert transmitted_packet.ipv4.dst == backend.ip
        assert transmitted_packet.device == backend.device
        #assert transmitted_packet.data == packet.data TODO handle checksum, same as NAT
    else:
        # process heartbeat
        backend = {
            'ip': packet.ipv4.src,
            'device': packet.device
        }
        if backend not in backends:
           assert backends.old.full
        assert transmitted_packet is None
