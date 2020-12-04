#include "os/network_verifast.h"

//@ #include "proof/ghost_map.gh"
//@ #include "bitops.gh"
//@ #include "nat.gh"
//@ #include "listutils.gh"

/*@

    fixpoint bool matches(list<bool> route, list<bool> ip) {
        return drop(32 - int_of_bits(0, take(8, route)), drop(8, route)) == drop(32 - int_of_bits(0, take(8, route)), ip);
    }

    fixpoint bool lpm(list<bool> dst_ip, list<bool> dst_length, list<bool> dst_device, list<bool> route, list<bool> device) {
        return !matches(route, dst_ip) || int_of_bits(0, take(8, route)) < int_of_bits(0, dst_length) || device == dst_device;
    }

@*/

void spec() {

    struct os_net_packet packet;
    struct os_net_ether_header* ether_header;
    struct os_net_ipv4_header* ipv4_header;

    bool ether_header_present = os_net_ether_header(packet, &ether_header);
    bool ipv4_header_present = os_net_get_ipv4_header(ether_header, &ipv4_header);

    bool packet_is_sent;
    uint32_t dst_route;
    uint8_t dst_length;
    uint16_t dst_device;
        
    
    // table = Map(Route, Device)
    //@ list< pair< list<bool>, list<bool> > > table;

    // IPv4 over Ethernet only
    //@ assert (ether_header_present || !packet_is_sent);
    //@ assert (ipv4_header_present || !packet_is_sent);
    
    // IP header validation
    // TODO: need to add checksum validation
    //@ assert (ipv4_header->time_to_live != 0 || !packet_is_sent);
    //@ assert (ipv4_header->version == 4 || !packet_is_sent);
    //@ assert (ipv4_header->ihl >= 20 || !packet_is_sent);
    //@ assert (ipv4_header->total_length >= ipv4_header.ihl || !packet_is_sent);

    /*@ if (packet_is_sent) {
         list<bool> b_dst_route = snd(bits_of_int(dst_route, N32));
         list<bool> b_dst_length = snd(bits_of_int(dst_length, N8));
         list<bool> b_dst_device = snd(bits_of_int(dst_device, N16));
         list<bool> route = append(b_dst_route, b_dst_length);
         list<bool> dst_ip = snd(bits_of_int(ipv4_header->dst_addr, N32));
        
         assert (ghostmap_get(table, route) == some(b_dst_device));
         assert (true == matches(route, dst_ip));
         assert (true == ghostmap_forall(table, (lpm)(dst_ip, b_dst_length, b_dst_device)));
     } @*/

    
}