from klint.verif.spec_utils import ExpiringSet

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

    flows = ExpiringSet(Flow, config["expiration time"], config["max flows"], packet.time)

    if packet.device == config["external device"]:
        flow = {
            'src_ip': packet.ipv4.dst,
            'dst_ip': packet.ipv4.src,
            'src_port': packet.tcpudp.dst,
            'dst_port': packet.tcpudp.src,
            'protocol': packet.ipv4.protocol
        }

        if flow not in flows.old:
            assert transmitted_packet is None
            return

        assert flows.did_refresh(flow)
    else:
        flow = {
            'src_ip': packet.ipv4.src,
            'dst_ip': packet.ipv4.dst,
            'src_port': packet.tcpudp.src,
            'dst_port': packet.tcpudp.dst,
            'protocol': packet.ipv4.protocol
        }

        if flow not in flows:
            assert flows.old.full

    assert transmitted_packet is not None
    assert transmitted_packet.data == packet.data
    assert transmitted_packet.device == 1 - packet.device
