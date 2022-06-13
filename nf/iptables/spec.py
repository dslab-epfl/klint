"""

Learnings:
- If you create a rule struct, you cannot access properties without the array-bracket-notation
- If you want to access properties of a key, you are not allowed to use the array-bracket-notation, otherwise it breaks
- prevent writing OR statmements, instead use if_then_else predicates
- structs can not be shifted, use concats instead

"""

MapKey = {
  'width': 'size_t',
  'is_dest_ip': 8,
  'dst_port': 16,
  'ipv4_addr': 32,
}

Command = {
  'is_dest_ip': 8,
  'dst_port': 16,
  'ipv4_addr': 32,
  'mask_width': 'size_t',
  'command_type': 32
}

def is_not_in_lpm(key, rule):
    shift = (8 + 16 + 32) - key.width
    lpm_key = key.ipv4_addr.concat(key.dst_port).concat(key.is_dest_ip) >> shift
    rule_key = rule["ipv4_addr"].concat(rule["dst_port"]).concat(rule["is_dest_ip"]) >> shift
    return (key.is_dest_ip != rule["is_dest_ip"]) | (key.dst_port != rule["dst_port"]) | (lpm_key != rule_key)

def spec(packet, config, transmitted_packet):
    rules = Map(MapKey,...)
   
    # check that the devices all are different
    assert config['send device'] != config['command device'] \
        and config['command device'] != config['check device'] \
        and config['send device'] != config['check device'], "different devices"

    # check the processing of a packet
    if packet.device == config['check device']:
        if packet.ipv4 is None or packet.tcpudp is None:
            assert transmitted_packet is None, "In case the packet isn't IPv4+TCP/UDP, it should not be forwarded"
            return

        # construct rules to search for them in the map
        src_rule = {
            'is_dest_ip': constant(0,8), # Source
            'dst_port': packet.tcpudp.src,
            'ipv4_addr': packet.ipv4.src,
        }
        dst_rule = {
            'is_dest_ip': constant(1,8), # Destination
            'dst_port': packet.tcpudp.dst,
            'ipv4_addr': packet.ipv4.dst,
        }
        src_rule_wildcard = {
            'is_dest_ip': constant(0,8), # Source
            'dst_port': constant(0,16),
            'ipv4_addr': packet.ipv4.src,
        }
        dst_rule_wildcard = {
            'is_dest_ip': constant(1,8), # Destination
            'dst_port': constant(0,16),
            'ipv4_addr': packet.ipv4.dst,
        }

        # if neither the src_rule nor the src_wild_rule and also neither the dst_rule nor the dst_wild_rule are in the MAP
        if (rules.forall(lambda k,v: is_not_in_lpm(k, src_rule)) and rules.forall(lambda k,v: is_not_in_lpm(k, src_rule_wildcard))) \
            or (rules.forall(lambda k,v: is_not_in_lpm(k, dst_rule)) and rules.forall(lambda k,v: is_not_in_lpm(k, dst_rule_wildcard))):
            assert transmitted_packet is None, "not routed packets should not be forwarded"

        else:
            assert transmitted_packet is not None, "routed packets should be forwarded"
            assert transmitted_packet.data == packet.data, "Packet data should not be modified"
            assert transmitted_packet.device == config['send device'], "Packets should be forwarded to the right device"


    elif packet.device == config['command device']: # in this case the packet was received on the command device
        # modify the db by adding new rules
        command = get_header(packet, Command)
        rule = {
            'width': command.mask_width,
            'is_dest_ip': command.is_dest_ip,
            'dst_port': command.dst_port,
            'ipv4_addr': command.ipv4_addr,
        }

        if command.command_type == 0:
            assert rule not in rules, "The rule should no longer be in the map"

        elif command.command_type == 1 and command.mask_width <= (8 + 16 + 32):
            if rules.old.length < config['capacity']:
                assert rule in rules, "The rule should be in the map if it's valid and the map has space"

        assert transmitted_packet is None, "Command packets should not be forwarded"

    else:
        assert packet.device == config['send device'], "or was it?"
        assert transmitted_packet is None, "Packets from the send device should not be transmitted"