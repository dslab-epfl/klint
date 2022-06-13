STATUS: Verified

# Iptables
The basic goal of this network function is to filter IP packets being forwarded by our network card.
We do not consider packets directly being destined to one of the network card physical device or being generated and sent by the network card.

The reason for this choice is that this NF function due to its formal verification property is meant to only be used in architecture that solely focus on handling network functions with dedicated small OS.

## Structure
### Config
The config file contains 3 devices:  
- `send device`: the device that will send the packet once it went through the blacklist
- `check device`: the device that will receive packets to be filtered
- `command device`: the device that will receive packets to update the black list state
- `capacity` that will define the number of blacklisted entries this nf can store

### Command structure
Commands update the state of the blacklist IPv4 addresses. It has the following structure:
```
{
   ipv4_addr: uint32_t,
   mask: int, // can only take the values 0xFFFFFFF, 0xFFFFFF00, 0xFFFF0000, 0xFF000000
   address_type: int, // 0 = source address, 1 = destination address
   port: uint16_t,
   rule_slot: size_t, // which rule slot should be used to store the rule
   cmd_type: int, // 0 = Remove, 1 = ADD
}
```

### Rule Structure
Rule represent the structure that can match black listed IP addresses
```
ipv4_address_rule
{
  ipv4_addr: uint_32;
  mask: int; // same as for command
  ipv4_address_type int // same as for command;
}
```

## Use Case
### Command received
Precondition: Packet is received from `command device`
1. Command is parsed from packet
2. If command type == Remove
   1. Remove the port from the whitelist (set the bitmap to false)
3. else
   1. Add the port the the whitelist (set the bitmap to true)

### Packet received
Precondition: packet is received from `check device`
1. Packet ip addresses are converted into rules
2. Rules are matched against the whitelist
3. If a rule matches
   1. The bitmap us checked if the source and destination ports are whitelisted
   2. If they are whitelisted
      1. Packet is sent via the device 'send device'
   3. Else
      1. Packet is dropped
4. Else
   1. Packet is dropped