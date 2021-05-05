def spec(pkt, config, sent_pkt):
  if pkt.ipv4 is None or pkt.tcpudp is None:
    assert sent_pkt is None
    return

  if pkt.device == config["external device"]:
    flow = {
      'src_ip': pkt.ipv4.dst,
      'dst_ip': pkt.ipv4.src,
      'src_port': pkt.tcpudp.dst,
      'dst_port': pkt.tcpudp.src,
      'protocol': pkt.ipv4.protocol
    }

    table = Map(typeof(flow), ...)

    if sent_pkt is not None:
      assert flow in table.old
      assert sent_pkt.data == pkt.data
      assert sent_pkt.device == 1 - pkt.device
