# This file is prefixed to all specifications.
# It contains core verification-related concepts, including the "_spec_wrapper" that is called by the verification engine.
# It communicates with the outside world via get/set_symbex.

from collections.abc import Callable
from typing import Any, Mapping, TypeVar

import claripy

from klint.verif.value_proxy import ValueProxy
from klint.verif.symbex_data import get_symbex, set_symbex

Device = "uint16_t"
Time = "uint64_t"

# === Typing ===
# Specs should not need to directly refer to any of these.
# This type and functions wrap and unwrap values for symbolic execution.

K = TypeVar('K')
V = TypeVar('V')

class TypedWrapper(dict[str, V]): # for convenience: use dict.item instead of dict['item']
    def __getattr__(self, item: str) -> V:
        return self[item]
    def __setattr__(self, item: str, value: V) -> None:
        self[item] = value

def type_size(type: Any) -> int:
    if isinstance(type, dict):
        return sum(type_size(v) for v in type.values())
    if isinstance(type, str):
        return int(getattr(get_symbex().state.sizes, type))
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
    for v in value.values():
        if result is None:
            result = v
        else:
            result = v.concat(result)
    if result.size() < type_size(type):
        result = result.zero_extend(type_size(type) - result.size())
    return result


# === Spec 'built-in' functions ===

# Get the type of 'value'
def typeof(value) -> int:
    if isinstance(value, dict):
        return sum(typeof(v) for v in value.values())
    return value.size()

def if_then_else(cond, thn, els):
    return get_symbex().state.solver.If(cond, thn, els)

# Existential quantifier, returns true iff there definitely exists a value that satisfies 'func'
# 'func' is a lambda with one parameter returning a bool
def exists(type, func):
    symbex = get_symbex()
    value = symbex.state.BVS("exists_value", type_size(type))
    return symbex.state.solver.satisfiable(extra_constraints=[func(type_wrap(value, type))])

# Constant with the given value and type, occasionally necessary
def constant(value, type):
    return get_symbex().state.BVV(value, type_size(type))


# === Maps ===

# This is the key to abstracting data structures in specs.
# Declare a Map(key_type, value_type) at the start of the spec, where value_type can be the literal '...' to mean you don't care
# Then use the methods/properties
# Verification will find one map in the implementation that corresponds to the specification map, or fail if there is no mapping such that the specification holds
# Beware, because this is existential ("there exists a map such that..."), specs have to be written in a "positive" fashion, such as asserting that items are added to the map
# If you write specs with only "negative" properties such as "if X then items are _not_ added to map M", this may hold for some map other than the specific one you had in mind,
# and then verification will succeed...
class Map:
    def __init__(self, key_type, value_type, _map=None):
        if _map is None:
            # Start with all candidates
            symbex = get_symbex()
            candidates = symbex.state.maps
            # Exclude the fractions and packets, which the spec writer is not even aware of
            candidates = filter(lambda c: "fracs_" not in c[1].meta.name and "packet_" not in c[1].meta.name, candidates)
            # Sort by key and value size differences, ensuring the candidates are at least as big as needed
            key_size = type_size(key_type)
            candidates = filter(lambda c: c[1].meta.key_size >= key_size, candidates)
            if value_type is ...:
                candidates = sorted(candidates, key=lambda c: (c[1].meta.key_size - key_size))
            else:
                value_size = type_size(value_type)
                candidates = filter(lambda c: c[1].meta.value_size >= value_size, candidates)
                candidates = sorted(candidates, key=lambda c: (c[1].meta.key_size - key_size) + (c[1].meta.value_size - value_size))
            # Now get the object; if we called choose on the map instead, it'd remain the same map across states, which would be bad
            obj = choose(list(map(lambda c: c[0], candidates)))
            _map = next(m for (o, m) in symbex.state.maps if o.structurally_match(obj))
            # Debug:
            #print(key_type, "->", value_type)
            #for (o, m) in candidates:
            #    print("  ", m, m.meta.key_size, m.meta.value_size)
            #print(" ->", _map)

        self._map = _map
        self._key_type = key_type
        self._value_type = None if value_type is ... else value_type

    # This returns a Map representing the state of this Map before processing the current packet
    @property
    def old(self):
        return Map(self._key_type, self._value_type, _map=self._map.oldest_version())

    def __contains__(self, key):
        (_, present) = self._map.get(get_symbex().state, type_unwrap(key, self._map.meta.key_size))
        return present

    def __getitem__(self, key):
        (value, present) = self._map.get(get_symbex().state, type_unwrap(key, self._map.meta.key_size))
        if not present:
            raise Exception("Spec called get but element may not be there")
        return type_wrap(value, self._value_type)

    # 'pred' is a lambda taking in key, value and returning bool
    def forall(self, pred):
        return self._map.forall(get_symbex().state, lambda k, v: pred(type_wrap(k, self._key_type), type_wrap(v, self._value_type)))

    # we can't override __len__ because python enforces that it returns an 'int'
    @property
    def length(self):
        return self._map.length()


# Special case for a single-element map, commonly used to store state
# Instead of declaring a Map(intptr_t, value_type), declare a Cell(value_type)
class Cell:
    def __init__(self, value_type):
        # Start with all candidates
        symbex = get_symbex()
        candidates = symbex.state.maps
        # Exclude maps with key size != ptr
        candidates = filter(lambda c: c[1].meta.key_size == symbex.state.sizes.ptr, candidates)
        # Exclude the fractions and packets, which the spec writer is not even aware of
        candidates = filter(lambda c: "fracs_" not in c[1].meta.name and "packet_" not in c[1].meta.name, candidates)
        # Exclude maps with length != 1
        candidates = filter(lambda c: not symbex.state.solver.satisfiable(extra_constraints=[c[1].length() != 1]), candidates)
        # Sort by value size difference, ensuring the candidates are at least as big as needed
        value_size = type_size(value_type)
        candidates = filter(lambda c: c[1].meta.value_size >= value_size, candidates)
        candidates = sorted(candidates, key=lambda c: (c[1].meta.value_size - value_size))
        # Now get the object; if we called choose on the map instead, it'd remain the same map across states, which would be bad
        obj = choose(list(map(lambda c: c[0], candidates)))
        self._map = next(m for (o, m) in symbex.state.maps if o.structurally_match(obj))
        self.value_type = value_type
        # Debug:
        #print("cell", value_type)
        #for (o, m) in candidates:
        #    print("  ", m, m.meta.value_size)
        #print(" ->", self._map)

    @property
    def value(self):
        symbex = get_symbex()
        return type_wrap(self._map.get(symbex.state, symbex.state.BVV(0, symbex.state.sizes.ptr))[0], self.value_type)

    @property
    def old_value(self):
        symbex = get_symbex()
        return type_wrap(self._map.oldest_version().get(symbex.state, symbex.state.BVV(0, symbex.state.sizes.ptr))[0], self.value_type)

# TODO: The 'choices' logic makes too many assumptions without checking them;
#       we need to make sure the requested choices are the same in all paths

def choose(choices: list[ValueProxy[claripy.ast.BV]]) -> ValueProxy[Any]:
    choices = [ValueProxy.unwrap(c) for c in choices]
    assert len(choices) != 0
    symbex = get_symbex()
    if symbex.choice_index == len(symbex.choices):
        symbex.choices.append(choices)
    else:
        assert [a is b for (a,b) in zip(choices, symbex.choices[symbex.choice_index])], "choices must be the same across all paths"
    # Exclude those we have used already
    while any(cs[0] is symbex.choices[symbex.choice_index][0] for cs in symbex.choices[:symbex.choice_index]):
        print("Dismissing dupe", symbex.choices[symbex.choice_index][0])
        symbex.choices[symbex.choice_index].pop(0)
    result = symbex.choices[symbex.choice_index][0]
    symbex.choice_index = symbex.choice_index + 1
    set_symbex(symbex)
    return ValueProxy.wrap(result)


# === Config ===

# The config object passed to the spec, has the config parameters as dictionary values (e.g. `config["thing"]`) plus a "devices_count" property
class _SpecConfig:
    def __init__(self, meta: Mapping[Any, Any], devices_count: int):
        self._meta = meta
        self._devices_count = devices_count

    @property
    def devices_count(self) -> int:
        return self._devices_count

    def __getitem__(self, index):
        if index not in self._meta:
            raise Exception("Unknown config item: " + str(index))
        return self._meta[index]


# === Network devices ===
# One of these two will be the `packet.device` value, you can use 'in' and `.length` on them

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
# See below for the exact properties, the idea is you can do e.g. `packet.ipv4 is None` or `packet.ether.dst` instead of writing the specific byte offsets

class _SpecPacketHeader:
    def __init__(self, state, map, offset, attrs):
        self.state = state
        self.map = map
        self.offset = offset
        self.attrs = attrs

    def __getattr__(self, attr):
        if attr == 'as_value':
            return super().__getattr__(attr)
        # Same logic as the heap plugin's read method
        # First find the attribute's offset and size
        offset = self.offset
        size = None
        for (name, sz) in self.attrs.items():
            if name == attr:
                size = type_size(sz)
                break
            offset += type_size(sz)
        if size is None:
            raise Exception("Unknown attribute: " + attr)
        # Convert the offset to index+offset
        index = offset // 8
        offset = offset % 8
        # Then read, in chunks if needed
        result = self.state.solver.BVV(0, 0)
        while result is None or result.size() < size + offset:
            chunk, present = self.map.get(self.state, self.state.solver.BVV(index, self.state.sizes.ptr))
            # Ensure we can read
            assert not self.state.solver.satisfiable(extra_constraints=[~present])
            # Remember the result
            result = chunk.concat(result)
            # Increment the index for the next chunk
            index = index + 1
        if offset != 0:
            result = result[:offset]
        if result.size() > size:
            result = result[size-1:0]
        return result

    def as_value(self):
        result = None
        for a in self.attrs:
            val = getattr(self, a)
            result = val if result is None else val.concat(result)
        return result


class _SpecPacketData:
    def __init__(self, state, map):
        self.state = state
        self.map = map

    def __eq__(self, other):
        return (self.map.length() == other.map.length()) & self.map.forall(self.state, lambda k, v: self.state.MapHas(other.map, k, value=v))

class _SpecPacket:
    def __init__(self, state, map, length, time, devices):
        self.map = map
        self.state = state
        self.length = length
        self.time = time
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
    def ether(self): # always set for now, we only support Ethernet packets
        return _SpecPacketHeader(self.state, self.map, 0, {
            'dst': 48,
            'src': 48,
            'type': 16
        })

    @property
    def ipv4(self):
        if self.ether.type == 0x0008: # TODO handle endianness in spec
            return _SpecPacketHeader(self.state, self.map, 48+48+16, {
                'ihl': 4,
                'version': 4,
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
            })
        return None

    @property
    def tcpudp(self):
        if self.ipv4 is not None and ((self.ipv4.protocol == 6) | (self.ipv4.protocol == 17)):
            return _SpecPacketHeader(self.state, self.map, (48+48+16)+(8+8+16+16+16+8+8+16+32+32), {
                'src': 16,
                'dst': 16
            })
        return None

    @property
    def data(self) -> _SpecPacketData:
        return _SpecPacketData(self.state, self.map)


# === Network 'built-in' functions ===

def get_header(packet, header_type, offset=0):
    return _SpecPacketHeader(packet.state, packet.map, offset, header_type)

def ipv4_checksum(header):
    return header.checksum # TODO actually compute it instead :-)


# === Spec wrapper ===

def _spec_wrapper(spec: Callable[..., None], data):
    state = get_symbex().state
    print("PATH", ValueProxy.unwrap(state).path._segments)

    received_packet_map = state.maps[data.network.received_addr].oldest_version()
    received_packet = _SpecPacket(state, received_packet_map, data.network.received_length, data.time, _SpecSingleDevice(data.network.received_device))

    transmitted_packet = None
    if len(data.network.transmitted) != 0:
        if len(data.network.transmitted) > 1:
            raise Exception("TODO support multiple transmitted packets")
        if data.network.transmitted[0].is_flood:
            transmitted_device = _SpecFloodedDevice(data.network.transmitted[0].device, data.devices_count)
        else:
            transmitted_device = _SpecSingleDevice(data.network.transmitted[0].device)
        transmitted_packet_map = state.maps[data.network.transmitted[0].data_addr]
        transmitted_packet = _SpecPacket(state, transmitted_packet_map, data.network.transmitted[0].length, None, transmitted_device)

    config = _SpecConfig(data.config, data.devices_count)

    spec(received_packet, config, transmitted_packet)
