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

    if packet.device == config["wan device"]:
        flow_index = packet.tcpudp.dst - config["start port"]
        flow = flows.old.get_by_index(flow_index)
        if flow is None:
            assert transmitted_packet is None
            return
        if (flow.dst_ip != packet.ipv4.src) | (flow.dst_port != packet.tcpudp.src) | (flow.protocol != packet.ipv4.protocol):
            assert transmitted_packet is None
            return

        assert flows.did_refresh(flow)
        assert transmitted_packet.ipv4.dst == flow.src_ip
        assert transmitted_packet.tcpudp.dst == flow.src_port
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
            assert transmitted_packet is None
            return

        assert transmitted_packet.ipv4.src == config["external addr"]
        assert transmitted_packet.tcpudp.src == config["start port"] + flows.get_index(flow)

    #assert transmitted_packet.data == packet.data # TODO handle the flow and checksum changes with a nice API for specs
    assert transmitted_packet.device == 1 - packet.device
