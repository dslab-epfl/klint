STATUS: Unverified

# Iptables Port Whitelist
To achieve an iptables like functionality, we created iptables_port_whitelist as the third iteration, where we just decide on forwarding a package or not, based on the condition that the source as well as the destination IPv4 address is on a whitelist as well as the correct port number and the received data is a valid IPv4 packet. To include the ports in the prefix of the lpm was not our first idea, since we went first with a bitmap as the lpm's value, where each port number has a bit. This turned out to be too complex for klint so we switched to the prefix-inclusion approach.
