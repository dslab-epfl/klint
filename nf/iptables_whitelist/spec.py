import pdb

MapKey = {
  'width': 'size_t',
  'is_dest_ip': 8,
  'ipv4_addr': 32,
}

Command = {
  'is_dest_ip': 8,
  'ipv4_addr': 32,
  'mask_width': 'size_t',
  'command_type': 32
}

def is_not_in_lpm(key, rule):
    shift = 40-key.width
    lpm_key = key.ipv4_addr.concat(key.is_dest_ip)
    shift_key = lpm_key >> shift
    shift_ip = rule["ipv4_addr"].concat(rule["is_dest_ip"]) >> shift
    return if_then_else(key.is_dest_ip == rule["is_dest_ip"],
                        shift_key != shift_ip,
                        True)

def spec(packet, config, transmitted_packet):
    blacklist_map = Map(MapKey,...)

    assert config['send device'] != config['command device'] \
        and config['command device'] != config['check device'] \
        and config['send device'] != config['check device'], "different devices"

    if packet.device == config['command device']:
        command = get_header(packet, Command)
        rule = command.ipv4_addr.concat(command.is_dest_ip)

        if command.command_type == 0:
            assert rule.concat(command.mask_width) not in blacklist_map, "The rule should no longer be in the map"

        elif command.command_type == 1 and command.mask_width <= 40:
            if blacklist_map.old.length < config['capacity']:
                assert rule.concat(command.mask_width) in blacklist_map, "The rule should be in the map if it's valid and the map has space"

    elif packet.device == config['check device']:
        if packet.ipv4 is None:
            assert transmitted_packet is None, "Non-IPv4 packets should not be forwarded"
            return

        src_rule = {
            'is_dest_ip': constant(0,8), # Source
            'ipv4_addr': packet.ipv4.src,
        }

        dst_rule = {
            'is_dest_ip': constant(1,8), # Destination
            'ipv4_addr': packet.ipv4.dst,
        }

        if not blacklist_map.forall(lambda k,v: is_not_in_lpm(k, src_rule)) and not blacklist_map.forall(lambda k,v: is_not_in_lpm(k, dst_rule)):
            assert transmitted_packet is not None, "white listed packets should be forwarded"
            assert transmitted_packet.data == packet.data, "Packet data should not be modified"
            assert transmitted_packet.device == config['send device'], "Packets should be forwarded to the right device"
        else:
            assert transmitted_packet is None, "Not whitelisted packets should not be forwarded"
    else:
        assert packet.device == config['send device'], "or was it?"
        assert transmitted_packet is None, "Packets from the send device should not be transmitted"
            
