Flow = {
    'src_ip': 32, 
    'dst_ip': 32, 
    'src_port': 16, 
    'dst_port': 16, 
    'protocol': 8
}

def spec(packet, config, transmitted_packet):
    if packet.ipv4 is None or packet.tcpudp is None:
        assert transmitted_packet is None
        return

    flows = ExpiringSet(Flow, config["expiration time"], config["max flows"])

    if packet.device == config["wan device"]:
        flow = {
            'src_ip': packet.ipv4.dst,
            'dst_ip': packet.ipv4.src,
            'src_port': packet.tcpudp.dst,
            'dst_port': packet.tcpudp.src,
            'protocol': packet.ipv4.protocol
        }
        print("HI",flow)

        if flow in flows.old:
            assert flows.did_refresh(flow)
            assert transmitted_packet == packet
        else:
            assert transmitted_packet is None
    else:
        flow = {
            'src_ip': packet.ipv4.src,
            'dst_ip': packet.ipv4.dst,
            'src_port': packet.tcpudp.src,
            'dst_port': packet.tcpudp.dst,
            'protocol': packet.ipv4.protocol
        }
        print("HI2",flow)

        assert flows.full or flow in flows
        assert transmitted_packet == packet
