STATUS: Not verified

# DHCP
This protocol is the protocol used by any device on a network using IPv4 in order to request and obtain an IP address.
The DHCP rfc can be found [here](https://datatracker.ietf.org/doc/html/rfc2131)

The protocol can be broken down into stages: `DHCP discover message` from client to server, `DHCP offer message` from server to client,
`DHCP request message` from client to server, `DHCP acknowledgment` message from server to client.

## DHCP header format
| field name | size in bytes | purpose                                                                                                           |
| ---------- | ------------- | ----------------------------------------------------------------------------------------------------------------- |
| op         | 1             | message opcode                                                                                                    |
| htype      | 1             | specifies the medium used in our case always ethernet                                                             |
| hlen       | 1             | specifies the size of the hardware address length                                                                 |
| hops       | 1             | number of hops from relay agents between client to server                                                         |
| xid        | 4             | transaction ID, a random number chosen by client and used by client and server to associate messages and response |
| secs       | 2             | second elapse since client began address aquisition or renewal process                                            |
| flags      | 2             | flags (unclear what they are used for)                                                                            |
| ciaddr     | 4             | only filed for the client is in BOUND,RENEW or REBINDING phase                                                    |
| yaddr      | 4             | clients IP address                                                                                                |
| siaddr     | 4             | IP address of the next server to use in DHCPOFFER, DHCPCK by server                                               |
| giaddr     | 4             | Relay agent IP address used in booting via a relay agent                                                          |
| chaddr     | 16            | client hardware address                                                                                           |
| sname      | 64            | Optional server host name                                                                                         |
| option     | var           | Optional fields                                                                                                   |

## Understanding the Option field
All the RFC information regarding the values that can be present in the `option` field for the DHCP protocol can be found [here](https://datatracker.ietf.org/doc/html/rfc1533). Here are the important aspects.  
An option entry is made of three things:
| Code                                                       | len                                                               | value |
| ---------------------------------------------------------- | ----------------------------------------------------------------- | ----- |
| represents a specific key associated with a specific field | represents the size of the value associated with the key in bytes | data  |

## DHCP purpose
### Allocation of network address
Here the goal for the DHCP server is to temporarily allocate an IP address to a client.
The protocol works as follow
1. Client requests an IP address for a period of time known as `lease`
2. DHCP servers grantees not to reallocate that address within the requested time and will return that seams address each time the client requests it

#### Conditions
- client may send a message to extend its lease
- client may issue a message to terminate its lease and release the address
- client may ask for an infinite lease
  - server still has the right to give a lengthy lease but not infinite
- server may reallocate addresses whose lease have expired

## Client IPv4 request protocol
*Note that this is based on the RFC but does not include all the optional steps as for now we will try to focus on a simpler version of the protocol*
*in order to reduce the work required to formally verify the nf* 
### Special information
- messages coming from client to server have their `op` filed set to `BOOTREQUEST` which has a value of 1
- message coming from server to client have their `op` filed set to `BOOTREPLY` which has a value of 2
- Step 1 to 12 can be skipped should the client decide to directly opt for a specific IP address

### Precondition
DHCP packet sent have a valid DHCP message format

1. Client broadcast a `DHCPDISCOVER` message
   1. DHCP option must contain in the order specified bellow the following and must be greater than 34 bytes in total to allow for the response to reuse the packet
      1. dhcp_message_type_option_code;
      2. dhcp_message_type_size;
      3. dhcp_message_type_value = DHCPDISCOVER;
      4. client_identifier_option_code;
      5. client_identifier_size;
      6. client_identifier_hardware_value;
      7. client_identifier_value[6];
      9. end_option_code
2. Server checks the validity of the DHCPDISCOVER message
3. Server creates a `DHCPOFFER` message
   1. set the yaddr filed to the IP address we want to give to the client
   2. set the gateway ip address in the option field
   3. set the dhcp ip address in the option field
   4. set the ip mask in the option field
   5. set the dns server address in the option field
   6. set the ip address lease time
4. Server set the eth_src_add to that of the DHCP server
5. Server set the eht_dst_add to that of the client
6. Server set the ip_src_add to that of the dhcp server
7. Server set the ip_dst_add to that of the newly assigned client IP address
8. Server set eth_addr_src to that of its own MAC address
9. Server set eth_addr_dst to that of the client MAC address
10. Server set the dst_port to that of the client src port
11. Server ser the src_port to that of the server src port
12. Server sends the packet back to the client
13. Client sends a DHCPREQUEST message to the selected server conf
   1. DHCP option must contain in the order specified bellow the following and must be greater than 34 bytes in total to allow for the response to reuse the packet
      1. dhcp_message_type_option_code;
      2. dhcp_message_type_size;
      3. dhcp_message_type_value = DHCPREQUEST;
      4. client_identifier_option_code;
      5. client_identifier_size;
      6. client_identifier_hardware_value;
      7. client_identifier_value[6];
      8. requested_ip_address_option_code
      9. requested_ip_address_size 
      10. requested_ip_address_value
      11. end_option_code
14. Server verifies the DHCP request message and checks that the IP address in the requested_ip_address value is the one that has been assigned to the client identifier given.
    1.  if valid server prepares a DHCPACK message
    2.  if invalid server prepares a DHCPNACK message
15. Server set the eth_src_add to that of the DHCP server
16. Server set the eht_dst_add to that of the client
17. Server set the ip_src_add to that of the dhcp server
18. Server set the ip_dst_add to that of the newly assigned client IP address
19. Server set eth_addr_src to that of its own MAC address
20. Server set eth_addr_dst to that of the client MAC address
21. Server set the dst_port to that of the client src port
22. Server set the src_port to that of the server src port
23. Server ser response back to the client.