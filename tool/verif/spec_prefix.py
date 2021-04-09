# This file is prefixed to all specifications.
# It contains core verification-related concepts, including the "_spec_wrapper" that is called by the verification engine.

from collections import namedtuple


# === Typing ===

def type_size(type):
    if isinstance(type, dict):
        return sum([type_size(v) for v in type.values()])
    if isinstance(type, int):
        return type
    if isinstance(type, str):
        global __symbex__
        return getattr(__symbex__.state.sizes, type)
    raise Exception(f"idk what to do with type '{type}'")


class TypedProxy:
    @staticmethod
    def wrap(value, type):
        if isinstance(type, dict):
            return TypedProxy(value, type)
        return value

    @staticmethod
    def unwrap(value):
        if not isinstance(value, TypedProxy):
            return value
        return value._value

    def __init__(self, value, type):
        assert value is not None and not isinstance(value, TypedProxy)
        assert type is not None and isinstance(type, dict)
        self._value = value
        self._type = type

    def __getattr__(self, name):
        if name[0] == "_":
            # Private members, for use within the class itself
            return super().__getattr__(name, value)

        assert name in self._type
        offset = 0
        for (k, v) in self._type.items(): # Python preserves insertion order from 3.7 (3.6 for CPython)
            if k == name:
                return ValueProxy(self._value[type_size(v)+offset-1:offset], type=v)
            offset = offset + type_size(v)


# === Spec 'built-in' functions ===

def exists(type, func):
    global __symbex__
    value = __symbex__.state.solver.BVS("exists_value", type_size(type))
    results = __symbex__.state.solver.eval_upto(func(value), 2)
    return results == [True]


# === Maps ===

class Map:
    def __init__(self, key_type, value_type):
        global __symbex__
        key_size = type_size(key_type)
        value_size = ... if value_type is ... else type_size(value_type)
        candidates = [m for m in __symbex__.state.maps if m.meta.key_size >= key_size and ((value_size is ...) or (m.meta.value_size == value_size))]
        # Ignore maps that the user did not declare
        candidates = [m for m in candidates if "allocated_" not in m.meta.name and "packet_" not in m.meta.name]
        if len(candidates) == 0:
            # TODO padding can mess things up, ideally this should do candidate_size >= desired_size and then truncate
            raise Exception("No such map.")

        self._map = __choose__(candidates)
        self._key_type = key_type
        self._value_type = None if value_type is ... else value_type

    def __contains__(self, key):
        global __symbex__
        (value, present) = self._map.get(__symbex__.state, TypedProxy.unwrap(key))
        return present

    # TODO friendlier API?
    def __getitem__(self, key):
        global __symbex__
        (value, present) = self._map.get(__symbex__.state, TypedProxy.unwrap(key))
        present_values = __symbex__.state.solver.eval_upto(present, 2)
        if present_values != [True]:
            raise Exception("Spec called get but element may not be there")
        return TypedProxy.wrap(value, self._value_type)

    def forall(self, pred):
        global __symbex__
        pred = MapInvariant.new(__symbex__.state, self._map.meta, lambda i: ~i.present | pred(TypedProxy.wrap(i.key, self._key_type), TypedProxy.wrap(i.value, self._value_type)))
        return self._map.forall(__symbex__.state, pred)

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


# === Network headers ===

_EthernetHeader = namedtuple(
    "_EthernetHeader", [
        "dst",
        "src",
        "type"
    ]
)

_IPv4Header = namedtuple(
    "_Ipv4Header", [
        # TODO other fields - don't care for now
        "version",
        "ihl",
        "total_length",
        "time_to_live",
        "protocol",
        "checksum",
        "src",
        "dst"
    ]
)

_TcpUdpHeader = namedtuple(
    "_TcpUdpHeader", [
        "src",
        "dst"
    ]
)


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
    def __init__(self, data, length, devices):
        self.data = data
        self.length = length
        self._devices = devices

    @property
    def device(self):
        if isinstance(self._devices, _SpecSingleDevice):
            return self._devices._device
        raise Exception("The packet was sent on multiple devices")

    @property
    def devices(self):
        return self._devices

    @property
    def ether(self):
        return _EthernetHeader(
            dst=self.data[6*8-1:0],
            src=self.data[12*8-1:6*8],
            type=self.data[14*8-1:12*8]
        )

    @property
    def ipv4(self):
        if self.ether is None:
            return None
        if self.ether.type != 0x0008: # TODO should explicitly handle endianness here (we're in LE)
            return None
        start = 14*8
        return _IPv4Header(
            version=self.data[start+4-1:start],
            ihl=self.data[start+8-1:start+4],
            total_length=self.data[start+4*8-1:start+2*8],
            time_to_live=self.data[start+9*8-1:start+8*8],
            protocol=self.data[start+10*8-1:start+9*8],
            checksum=self.data[start+12*8-1:start+10*8],
            src=self.data[start+16*8-1:start+10*8],
            dst=self.data[start+20*8-1:start+16*8]
        )

    @property
    def tcpudp(self):
        if self.ipv4 is None:
            return None
        if (self.ipv4.protocol != 6) & (self.ipv4.protocol != 17):
            return None

        return _TcpUdpHeader(
            src=self.data[36*8-1:34*8],
            dst=self.data[38*8-1:36*8]
        )


# === Network 'built-in' functions ===

def ipv4_checksum(header):
    return header.checksum # TODO





# === Spec wrapper ===

def _spec_wrapper(data):
    received_packet = _SpecPacket(data.network.received, data.network.received_length, _SpecSingleDevice(data.network.received_device))
    
    transmitted_packet = None
    if data.network.transmitted:
        if len(data.network.transmitted) > 1:
            raise Exception("TODO support multiple transmitted packets")
        tx_dev_int = data.network.transmitted[0][2]
        if tx_dev_int is None:
            transmitted_device = _SpecFloodedDevice(data.network.received_device, data.devices_count)
        else:
            transmitted_device = _SpecSingleDevice(tx_dev_int)
        transmitted_packet = _SpecPacket(data.network.transmitted[0][0], data.network.transmitted[0][1], transmitted_device)

    config = _SpecConfig(data.config, data.devices_count)

    spec(received_packet, config, transmitted_packet)
