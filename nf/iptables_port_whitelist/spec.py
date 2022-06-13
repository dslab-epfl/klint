MapKey = {
  'width': 'size_t',
  'address_type': 8,
  'ipv4_address': 32,
}

Command = {
  'address_type': 8,
  'ipv4_addr': 32,
  'mask_width': 'size_t',
  'bit_map_port': 128*8,
  'command_type': 32
}

def is_not_in_lpm(key, ip_src, ip_dst):
    shift = 40-key.width
    lpm_key = key.ipv4_address.concat(key.address_type)
    shift_key = lpm_key >> shift
    return if_then_else(
        key.address_type == 0,
        ip_src.concat(constant(0,8)) >> shift != shift_key,
        if_then_else(
            key.address_type == 1,
            ip_dst.concat(constant(1,8)) >> shift != shift_key,
            True # other command types are not allowed anyway
        )
    )

def spec(packet, config, transmitted_packet):
    blacklist_map = Map(MapKey,...)

    assert config['command device'] != config['check device']

    if packet.device == config['command device']:
        command = get_header(packet, Command)
        rule = command.ipv4_addr.concat(command.address_type)

        if command.command_type == 0:
            assert rule.concat(command.mask_width) not in blacklist_map, "The rule should no longer be in the map"

        elif command.command_type == 1 and command.mask_width <= 40:
            if blacklist_map.old.length < config['capacity']:
                assert rule.concat(command.mask_width) in blacklist_map, "The rule should be in the map if it's valid and the map has space"
    # elif packet.device == config['check device']:
    #     if packet.ipv4 is None:
    #         assert transmitted_packet is None, "Non-IPv4 packets should not be forwarded"
    #         return

    #     if blacklist_map.forall(lambda k,v: is_not_in_lpm(k, packet.ipv4.src, packet.ipv4.dst)):
    #         assert transmitted_packet is not None, "Non-blacklisted packets should be forwarded"
    #         assert transmitted_packet.data == packet.data, "Packet data should not be modified"
    #         assert transmitted_packet.device == config['send device'], "Packets should be forwarded to the right device"
    #     else:
    #         assert transmitted_packet is None, "Blacklisted packets should not be forwarded"
