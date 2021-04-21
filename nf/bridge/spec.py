# IEEE 802.1D
def spec(packet, config, transmitted_packet):
    # === §7.7.1 Active topology enforcement === #
    # "Each Port is selected as a potential transmission Port if, and only if [...] The Port considered for transmission is not the Port on which the frame was received [...]"
    if transmitted_packet is not None:
        assert ~(packet.device in transmitted_packet.devices)


    # === §7.8 The Learning Process === #
    # "The Learning Process shall create or update a Dynamic Filtering Entry (7.9, 7.9.2) in the Filtering Database, 
    #  associating the MAC Address in the source address field of the frame with the receiving Port, if and only if [...] 
    #  The source address field of the frame denotes a specific end station (i.e., is not a group address)"
    # note: an Ethernet address is a group address if the least significant bit of its first octet is set to 1
    db = Map(48, ...) # TODO typeof(packet.ether.src) (just returning the size in bits would already be good)
    #assert (packet.ether.src not in db) | ((packet.ether.src & 0x01_00_00_00_00_00) == 0)


    # === §7.9.5 Querying the Filtering Database === #
    # No quote here, the spec just alludes to this in many places
    if packet.ether.dst not in db:
        assert transmitted_packet.devices.length == config.devices_count - 1
