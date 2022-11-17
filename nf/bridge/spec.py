from klint.verif.spec_prefix import Cell, Device, Map, typeof

SpanningTreeState = {
    'update_time': 64,
    'my_id': 64,
    'root_id': 64,
    'root_cost': 32,
    'root_device': Device
}

# IEEE 802.1D
def spec(packet, config, transmitted_packet):
    stp_state = Cell(SpanningTreeState)
    db = Map(typeof(packet.ether.src), ...)

    if packet.ether is None:
        assert transmitted_packet is None
        return

    if packet.time > stp_state.old_value.update_time + config["stp update time"]:
        assert stp_state.value.update_time == packet.time
        return

    if packet.ether.dst == 0x00_00_00_C2_80_01: # note the endianness
        # spanning tree stuff
        return

    # === §7.7.1 Active topology enforcement === #
    # "Each Port is selected as a potential transmission Port if, and only if [...] The Port considered for transmission is not the Port on which the frame was received [...]"
    if transmitted_packet is not None:
        assert packet.device not in transmitted_packet.devices

    # === §7.8 The Learning Process === #
    # "The Learning Process shall create or update a Dynamic Filtering Entry (7.9, 7.9.2) in the Filtering Database, 
    #  associating the MAC Address in the source address field of the frame with the receiving Port, if and only if [...] 
    #  The source address field of the frame denotes a specific end station (i.e., is not a group address)"
    # note: an Ethernet address is a group address if the least significant bit of its first octet is set to 1
    # TODO this should be an invariant?
    #if packet.ether.src in db:
    #    assert (packet.ether.src & 1) == 0 # note the endianness

    # === §7.9.5 Querying the Filtering Database === #
    # No quote here, the spec just alludes to this in many places
    if packet.ether.dst not in db:
        assert transmitted_packet.devices.length == config.devices_count - 1
