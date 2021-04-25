# This file is prefixed to all specifications.
# It contains core verification-related concepts, including the "_spec_wrapper" that is called by the verification engine.
# It "talks" to the outside world via the global __symbex__ variable.


# === Typing ===

class TypedWrapper(dict): # for convenience: use dict.item instead of dict['item']
    def __getattr__(self, item):
        return self[item]
    def __setattr__(self, item, value):
        self[item] = value

def type_size(type):
    if isinstance(type, dict):
        return sum([type_size(v) for v in type.values()])
    if isinstance(type, str):
        global __symbex__
        return int(getattr(__symbex__.state.sizes, type))
    return int(type)

def type_wrap(value, type):
    if not isinstance(type, dict):
        return value
    result = TypedWrapper()
    offset = 0
    for (k, v) in type.items(): # Python preserves insertion order from 3.7 (3.6 for CPython)
        result[k] = value[type_size(v)+offset-1:offset]
        offset = offset + type_size(v)
    return result

def type_unwrap(value, type):
    if type is None:
        return value
    if not isinstance(value, dict):
        if value.size() < type_size(type):
            value = value.zero_extend(type_size(type) - value.size())
        return value
    if isinstance(type, dict):
        assert value.keys() == type.keys(), "please don't cast in weird ways"
        return value
    assert len(value) != 0, "please don't use empty dicts"
    # almost a proxy, let's handle it here...
    result = None
    total_size = 0
    for v in value.values():
        if result is None:
            result = v
        else:
            result = v.concat(result)
    if result.size() < type_size(type):
        result = result.zero_extend(type_size(type) - result.size())
    return result


# === Spec 'built-in' functions ===

def exists(type, func):
    global __symbex__
    value = __symbex__.state.BVS("exists_value", type_size(type))
    results = __symbex__.state.solver.eval_upto(func(type_wrap(value, type)), 2)
    return results == [True]


# === Maps ===

class Map:
    def __init__(self, key_type, value_type, _map=None):
        global __symbex__

        if _map is None:
            # Start with all candidates
            candidates = __symbex__.state.maps
            # Exclude the fractions and packets, which the spec writer is not even aware of
            candidates = filter(lambda c: "fracs_" not in c[1].meta.name and "packet_" not in c[1].meta.name, candidates)
            # Exclude those we have used already
            candidates = filter(lambda c: all(not choices[0].structurally_match(c[0]) for choices in __symbex__.choices[:__symbex__.choice_index]), candidates)
            # Sort by key and value size differences, ensuring the candidates are at least as big as needed
            key_size = type_size(key_type)
            candidates = filter(lambda c: c[1].meta.key_size >= key_size, candidates)
            if value_type is ...:
                candidates = sorted(candidates, key=lambda c: (c[1].meta.key_size - key_size))
            else:
                value_size = type_size(value_type)
                candidates = filter(lambda c: c[1].meta.value_size >= value_size, candidates)
                candidates = sorted(candidates, key=lambda c: (c[1].meta.key_size - key_size) + (c[1].meta.value_size - value_size))
            # This should never happen
            if len(candidates) == 0:
                raise Exception("No such map: " + str(key_type) + " -> " + str(value_type))
            # Debug:
            #print(key_type, "->", value_type)
            #for (o, m) in candidates:
            #    print("  ", m, m.meta.key_size, m.meta.value_size)
            # Now get the object; if we called choose on the map instead, it'd remain the same map across states, which would be bad
            candidates = map(lambda c: c[0], candidates)
            obj = __choose__(candidates)
            _map = next(m for (o, m) in __symbex__.state.maps if o.structurally_match(obj))

        self._map = _map
        self._key_type = key_type
        self._value_type = None if value_type is ... else value_type

    @property
    def old(self):
        return Map(self._key_type, self._value_type, _map=self._map.oldest_version())

    def __contains__(self, key):
        global __symbex__
        (_, present) = self._map.get(__symbex__.state, type_unwrap(key, self._map.meta.key_size))
        return present

    def __getitem__(self, key):
        global __symbex__
        (value, present) = self._map.get(__symbex__.state, type_unwrap(key, self._map.meta.key_size))
        if not present:
            raise Exception("Spec called get but element may not be there")
        return type_wrap(value, self._value_type)

    def forall(self, pred):
        global __symbex__
        return self._map.forall(__symbex__.state, lambda k, v: pred(type_wrap(k, self._key_type), type_wrap(v, self._value_type)))

    # we can't override __len__ because python enforces that it returns an 'int'
    @property
    def length(self):
        return self._map.length()


# === Config ===

class _SpecConfig:
    def __init__(self, meta, devices_count):
        self._meta = meta
        self._devices_count = devices_count

    @property
    def devices_count(self):
        return self._devices_count

    def __getitem__(self, index):
        if index not in self._meta:
            raise Exception("Unknown config item: " + str(index))
        return self._meta[index]


# === Network devices ===

class _SpecFloodedDevice:
    def __init__(self, orig_device, devices_count):
        self._orig_device = orig_device
        self._devices_count = devices_count

    def __contains__(self, item):
        return item != self._orig_device

    @property
    def length(self):
        return self._devices_count - 1

class _SpecSingleDevice:
    def __init__(self, device):
        self._device = device

    def __contains__(self, item):
        return item == self._device

    @property
    def length(self):
        return 1


# === Network packet ===

class _SpecPacket:
    _ETHER_HEADER = {
        'dst': 48,
        'src': 48,
        'type': 16
    }
    _IPV4_HEADER = {
        'version': 4,
        'ihl': 4,
        'dscp': 6,
        'ecn': 2,
        'total_length': 16,
        'identification': 16,
        'flags': 3,
        'fragment_offset': 13,
        'time_to_live': 8,
        'protocol': 8,
        'checksum': 16,
        'src': 32,
        'dst': 32
    }
    _TCPUDP_HEADER = {
        'src': 16,
        'dst': 16
    }

    def __init__(self, data, length, time, devices):
        self.length = length
        self.time = time
        self._devices = devices
        self.ether = type_wrap(data, _SpecPacket._ETHER_HEADER)
        self._rest = data[:type_size(_SpecPacket._ETHER_HEADER)]
        self.ipv4 = None
        self.tcpudp = None
        if self.ether.type == 0x0008: # TODO handle endness in spec
            self.ipv4 = type_wrap(data[:type_size(_SpecPacket._ETHER_HEADER)], _SpecPacket._IPV4_HEADER)
            self._rest = self._rest[:type_size(_SpecPacket._IPV4_HEADER)]
            if (self.ipv4.protocol == 6) | (self.ipv4.protocol == 17):
                self.tcpudp = type_wrap(data[:type_size(_SpecPacket._ETHER_HEADER)+type_size(_SpecPacket._IPV4_HEADER)], _SpecPacket._TCPUDP_HEADER)
                self._rest = self._rest[:type_size(_SpecPacket._TCPUDP_HEADER)]

    @property
    def device(self):
        if isinstance(self._devices, _SpecSingleDevice):
            return self._devices._device
        raise Exception("The packet was sent on multiple devices")

    @property
    def devices(self):
        return self._devices

    @property
    def data(self):
        full = type_unwrap(self.ether, type_size(_SpecPacket._ETHER_HEADER))
        if self.ipv4 is not None:
            full = type_unwrap(self.ipv4, type_size(_SpecPacket._IPV4_HEADER)).concat(full)
            if self.tcpudp is not None:
                full = type_unwrap(self.tcpudp, type_size(_SpecPacket._TCPUDP_HEADER)).concat(full)
        full = self._rest.concat(full)
        return full


# === Network 'built-in' functions ===

def ipv4_checksum(header):
    return header.checksum # TODO


# === Spec wrapper ===

def _spec_wrapper(data):
    global __symbex__
    #print("PATH", __symbex__.state._value.path._segments)

    received_packet = _SpecPacket(data.network.received, data.network.received_length, data.time, _SpecSingleDevice(data.network.received_device))
    
    transmitted_packet = None
    if len(data.network.transmitted) != 0:
        if len(data.network.transmitted) > 1:
            raise Exception("TODO support multiple transmitted packets")
        tx_dev_int = data.network.transmitted[0][2]
        if tx_dev_int is None:
            transmitted_device = _SpecFloodedDevice(data.network.received_device, data.devices_count)
        else:
            transmitted_device = _SpecSingleDevice(tx_dev_int)
        transmitted_packet = _SpecPacket(data.network.transmitted[0][0], data.network.transmitted[0][1], None, transmitted_device)

    config = _SpecConfig(data.config, data.devices_count)

    spec(received_packet, config, transmitted_packet)
