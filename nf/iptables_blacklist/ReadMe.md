STATUS: Verified

# Iptables Blacklist
To achieve an iptables like functionality, we created iptables_blacklist as the first iteration, where we just decide on forwarding a package or not, based on the condition that the source as well as the destination IPv4 address is not on a blacklist and the received data is a valid IPv4 packet.