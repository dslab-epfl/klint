# This file is prefixed to all specifications.
# It contains core verification-related concepts, including the "_spec_wrapper" that is called by the verification engine.

from collections import namedtuple


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


# === Config ===

class _SpecConfig:
    def __init__(self, meta, devices_count):
        self._meta = meta
        self._devices_count = devices_count

    @property
    def devices_count(self):
        return self._devices_count

    def __getitem__(self, index):
        global __state__
        global __type_size__
        print("HELLO", index, self._meta)
        print("WORLD", self._meta[index])
        for (k, v) in globals().items():
            print("GLOBAL", k, v)
        print("XXX", __state__)
        print("XXX", __type_size__)
        if index not in self._meta:
            raise Exception("Unknown config item: " + str(index))
        return self._meta[index]


# === Maps ===

# TODO use __contains__ for has, __getitem__ for get?
class Map:
    def __init__(self, key_type, value_type):
        key_size = __type_size__(key_type)
        value_size = ... if value_type is ... else __type_size__(value_type)
        candidates = [m for m in __state__.maps if m.meta.key_size >= key_size and ((value_size is ...) or (m.meta.value_size == value_size))]
        # Ignore maps that the user did not declare
        candidates = [m for m in candidates if "allocated_" not in m.meta.name and "packet_" not in m.meta.name]
        if len(candidates) == 0:
            # TODO padding can mess things up, ideally this should do candidate_size >= desired_size and then truncate
            raise Exception("No such map.")

        self._map = __choose__(candidates)
        #self._key_type = key_type
        #self._real_key_type = map.meta.key_size
        #self._value_type = None if value_type is ... else value_type

    def has(self, key):
        (value, present) = self._map.get(__state__, key) # of type=self._real_key_type...
        return present

    # TODO friendlier API?
    def get(self, key):
        (value, present) = self._map.get(__state__, key) # of type=self._real_key_type...
        if utils.can_be_false(__state__.solver, present):
            raise Exception("Spec called get but element may not be there")
        return value # of self._value_type...

    def forall(self, pred):
        pred = MapInvariant.new(__state__, self._map.meta, lambda i: ~i.present | pred(i.key, i.value)) # of types self._key_type / _value_type...
        return self._map.forall(__state__, pred)

    @property
    def length(self):
        return self._map.length()


# === Spec 'built-in' functions ===

def exists(type, func):
    value = __state__.solver.BVS("exists_value", __type_size__(type))
    results = __state__.solver.eval_upto(func(value), 2)
    return results == [True]


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
