import angr
import claripy
from collections import namedtuple
from datetime import datetime
import inspect
import os
from pathlib import Path

from .common import *
from binary import bitsizes
from binary import utils
from binary.externals.os import config as os_config
from binary.externals.os import network as os_network
from binary.ghost_maps import *
from python import executor as py_executor


class SpecMap:
    def __init__(self, state, map, key_type, value_type):
        self._state = state
        self._map = map
        self._key_type = key_type
        self._real_key_type = map.meta.key_size
        self._value_type = None if value_type is ... else value_type

    def has(self, key):
        (value, present) = self._map.get(self._state, ValueProxy.extract(key, type=self._real_key_type))
        return ValueProxy(self._state, present)

    def get(self, key):
        (value, present) = self._map.get(self._state, ValueProxy.extract(key, type=self._real_key_type))
        if utils.definitely_false(self._state.solver, present):
            raise VerificationException("Spec called get but element is definitely not there")
        return ValueProxy(self._state, value, self._value_type)

    def forall(self, pred):
        pred = MapInvariant.new(self._state, self._map.meta, lambda i: ValueProxy.extract(~i.present | pred(ValueProxy(self._state, i.key, self._key_type), ValueProxy(self._state, i.value, self._value_type))))
        return ValueProxy(self._state, self._map.forall(self._state, pred))

    @property
    def length(self):
        return ValueProxy(self._state, self._map.length())


def map_new(state, key_type, value_type):
    key_size = type_size(key_type) * 8
    value_size = ... if value_type is ... else type_size(value_type) * 8
    candidates = [m for (o, m) in state.maps if m.meta.key_size >= key_size and ((value_size is ...) or (m.meta.value_size == value_size))]
    # Ignore maps that the user did not declare
    candidates = [m for m in candidates if "allocated_" not in m.meta.name and "packet_" not in m.meta.name]
    if len(candidates) == 0:
        # TODO padding can mess things up, ideally this should do candidate_size >= desired_size and then truncate
        raise VerificationException("No such map.")
    candidate = candidates[state.choice_index]
    state.choice_index = state.choice_index + 1
    state.choice_remaining = len(candidates) > state.choice_index
    return SpecMap(state, candidate, key_type, value_type)


def exists(state, type, func):
    value = ValueProxy(state, claripy.BVS("exists_value", type_size(type) * 8), type)
    return utils.can_be_true(state.solver, ValueProxy.extract(func(value)))

def typeof(state, obj):
    return ValueProxy.extract(obj).size()

def ipv4_checksum(state, header):
    return header.checksum # TODO

externals = {
    "Map": map_new,
    "exists": exists,
    "typeof": typeof,
    "ipv4_checksum": ipv4_checksum
}

def handle_externals(name, *args, **kwargs):
    global current_state

    ext = externals[name]
    if inspect.isclass(ext): # it's a SimProcedure
        ext_inst = ext()
        ext_inst.state = current_state
        args = [a if isinstance(a, claripy.ast.base.Base) else claripy.BVV(a, bitsizes.size_t) for a in args]
        result = ext_inst.run(*args)
        if result.size() == bitsizes.bool and not result.symbolic:
            return not result.structurally_match(claripy.BVV(0, bitsizes.bool))
        return result
    else:
        return ext(current_state, *args)


def verify(data, spec):
    global current_state
    current_state = create_angr_state(data.constraints)
    current_state.maps = data.maps
    current_state.path = data.path # useful for debugging

    packet = SpecPacket(current_state, data.network.received, data.network.received_length, SpecSingleDevice(current_state, data.network.received_device))

    transmitted_packet = None
    if data.network.transmitted:
        if len(data.network.transmitted) > 1:
            raise "TODO support multiple transmitted packets"
        tx_dev_int = data.network.transmitted[0][2]
        transmitted_device = SpecFloodedDevice(current_state, data.network.received_device) if tx_dev_int is None else SpecSingleDevice(current_state, tx_dev_int) 
        transmitted_packet = SpecPacket(current_state, data.network.transmitted[0][0], data.network.transmitted[0][1], transmitted_device)

    current_state.choice_index = 0 # TODO support multiple maps
    current_state.choice_remaining = False
    current_state.choice_errors = []

    while True:
        try:
            result = py_executor.execute(
                spec_text=spec,
                spec_fun_name="spec",
                spec_args=[packet, data.config, transmitted_packet], # TODO: add device count somewhere... maybe make it an attr (not item) of config
                spec_external_names=externals.keys(),
                spec_external_handler=handle_externals
            )
            if result is not None:
                raise VerificationException("Spec returned something, it should not")
        except VerificationException as e:
            current_state.choice_errors.append(str(e))
            if not current_state.choice_remaining:
                print("NF verif failed:", "\n".join(current_state.choice_errors))
                break
        else:
            print("NF verif done! at", datetime.now())
            break