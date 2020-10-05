Flow = Struct({'src_ip': 32, 'dst_ip': 32, 'src_port': 16, 'dst_port': 16, 'protocol': 8})

NatTransmitFlags = TransmitFlags.UPDATE_ETHERNET_ADDRESSES | TransmitFlags.UPDATE_IPV4_CHECKSUM | TransmitFlags.UPDATE_TCPUDP_CHECKSUM

def spec(packet, config, state, sent_packets):
    if packet.ipv4 is None or packet.tcpudp is None:
        assert sent_packets == []

    flow_map = state.structs.get_expirable_map(Flow, config["max flows"])
    time = state.clock.now()

    if packet.device == config["external port"]:
        flow_index = packet.tcpudp.dst_port - config["start port"]
        flow = flow_map.get_by_index(flow_index, time, config["expiration time"])
        if flow is not None and flow.dst_ip == packet.ipv4.src_addr and flow.dst_port == packet.tcpudp.src_port and flow.protocol == packet.ipv4.protocol:
            packet.ipv4.dst_addr = flow.src_ip
            packet.tcpudp.dst_port = flow.src_port
            assert sent_packets == [(packet, 1 - config["external port"], NatTransmitFlags)]
    else:
        flow = Flow(packet.ipv4.src_addr, packet.ipv4.dst_addr, packet.tcpudp.src_port, packet.tcpudp.dst_port, packet.ipv4.protocol)
        index = flow_map.get_by_item(flow, time) or flow_map.add(flow, time)
        if index is None:
            assert not flow_map.expire_item(time, config["expiration time"])
            assert sent_packets == []
        else:
            packet.ipv4.src_addr = config["external address"]
            packet.tcpudp.src_port = config["start port"] + index
            assert sent_packets == [(packet, config["external port"], NatTransmitFlags)]
