STATUS: Verified

# Iptables Whitelist
To achieve an iptables like functionality, we created iptables_whitelist as the second iteration, where we just decide on forwarding a package or not, based on the condition that the source as well as the destination IPv4 address is on a whitelist and the received data is a valid IPv4 packet. The process of inverting the condition from the iptables_blacklist was getting us first into some problems, which we then were able to fix.