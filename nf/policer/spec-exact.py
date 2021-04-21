PolicerBucket = {
    "size": "uint64_t",
    "time": "time_t"
}

def spec(packet, config, devices_count):
    buckets = Array(config["max flows"], PolicerBucket)
    addresses = ExpiringSet(config["max flows"], "uint32_t")

    if devices_count != 2:
        return

    if packet.ether is None or packet.ipv4 is None:
        return

    if packet.device == config["wan device"]:
        index = addresses.get(packet.ipv4.dst)
        if index is None:
            if packet.length <= config["burst"] and addresses.try_add(packet.ipv4.dst):
                buckets[index].size = burst - packet.length
                buckets[index].time = packet.time
            else:
                return
        else:
            time_diff = time - buckets[index].time
            if time_diff < config["burst"] / config["rate"]:
                buckets[index].size += time_diff * config["rate"]
                if buckets[index].size > burst:
                    buckets[index].size = burst
            else:
                buckets[index].size = burst;

            buckets[index].time = packet.time

            if buckets[index].size <= packet.length:
                return
            buckets[index].size -= packet.length

    transmit(packet, 1 - packet.device)
