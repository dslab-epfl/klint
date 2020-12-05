import angr
from angr.state_plugins.solver import SimSolver
from archinfo.arch_amd64 import ArchAMD64
import claripy

from .defs import *
from binary import bitsizes
from binary import utils
from binary.memory_fractional import FractionalMemory


class VerificationException(Exception): pass


class TypeProxy:
    def __init__(self, state, value, type):
        self._state = state
        self._value = value
        self._type = type

    def __getattr__(self, name):
        if name[0] == "_":
            return super().__getattr__(name, value)
        if name in self._type:
            offset = 0
            for (k, v) in self._type.items(): # Python preserves insertion order from 3.7 (3.6 for CPython)
                if k == name:
                    return self._value[type_size(self._state, v)+offset:offset]
                offset = offset + type_size(self._state, v)
        raise VerificationException(f"idk what to do about attr '{name}'")

    def __setattr__(self, name, value):
        if name[0] == "_":
            return super().__setattr__(name, value)
        raise "TODO"

def type_size(state, type):
    if isinstance(type, str):
        return getattr(bitsizes, type) // 8
    if isinstance(type, dict):
        return sum([type_size(state, v) for v in type.values()])
    raise VerificationException(f"idk what to do with type '{type}'")

def type_cast(state, value, type):
    if isinstance(type, str):
        return value # already cast
    if isinstance(type, dict):
        return TypeProxy(state, value, type)
    raise VerificationException(f"idk what to do with type '{type}'")


class ValueProxy:
    def __init__(self, state, value):
        assert value is not None
        assert not isinstance(value, ValueProxy)
        self._state = state
        self._value = value

    def __getattr__(self, name):
        if name == "_raw":
            return self._value
        if name[0] == "_":
            return super().__getattr__(name, value)
        result = getattr(self._value, name)
        return ValueProxy(self._state, result)

    def __setattr__(self, name, value):
        if name[0] == "_":
            return super().__setattr__(name, value)
        raise "TODO"

    def __repr__(self):
        return self._value.__repr__()

    def _op(self, other, op):
        # We live in the magical world where nothing ever overflows... almost, we still live in QF_BV, let's use 128 bits to be safe
        BITSIZE = 128

        other_value = other
        self_value = self._value

        # Convert if needed
        if isinstance(other, ValueProxy):
            other_value = other._value
        if isinstance(other_value, float) and other_value == other_value // 1:
            other_value = int(other_value)
        if not isinstance(other_value, claripy.ast.Base):
            if isinstance(other_value, int):
                other_value = claripy.BVV(other_value, BITSIZE)

        if isinstance(self_value, claripy.ast.BV):
            self_value = self_value.zero_extend(BITSIZE - self_value.size())
            other_value = other_value.zero_extend(BITSIZE - other_value.size())

        return ValueProxy(self._state, getattr(self_value, op)(other_value))


    def __bool__(self):
        result = utils.get_if_constant(self._state.solver, self._value)
        if result is None:
            raise "TODO"
        return result

    def __eq__(self, other):
        return self._op(other, "__eq__")

    def __ne__(self, other):
        return self._op(other, "__ne__")

    def __lt__(self, other):
        return self._op(other, "ULT") # TODO: signedness...

    def __le__(self, other):
        return self._op(other, "ULE")

    def __gt__(self, other):
        return self._op(other, "UGT")

    def __ge__(self, other):
        return self._op(other, "UGE")

    def __mul__(self, other):
        return self._op(other, "__mul__")


class SpecPacket:
    def __init__(self, state, network_meta):
        self._state = state
        self._data_addr = network_meta.received_addr
        self.data = network_meta.received
        self.length = network_meta.received_length
        self.device = network_meta.received_device

    @property
    def ether(self):
        return ValueProxy(self._state, EthernetHeader(
            dst=self.data[6*8-1:0],
            src=self.data[12*8-1:6*8],
            type=self.data[14*8-1:12*8]
        ))

    @property
    def ipv4(self):
        if self.ether is None:
            return None
        is_ipv4 = self.ether._raw.type == 0x0008 # TODO should explicitly handle endianness here (we're in LE)
        if utils.definitely_true(self._state.solver, is_ipv4):
            start = 14*8
            return ValueProxy(self._state, IPv4Header(
                version=self.data[start+4-1:start],
                ihl=self.data[start+8-1:start+4],
                total_length=self.data[start+4*8-1:start+2*8],
                time_to_live=self.data[start+9*8-1:start+8*8],
                protocol=self.data[start+10*8-1:start+9*8],
                src=self.data[start+16*8-1:start+10*8],
                dst=self.data[start+20*8-1:start+16*8]
            ))
        elif utils.definitely_false(self._state.solver, is_ipv4):
            return None
        raise VerificationException("May or may not be IPv4; this case isn't handled yet")

    @property
    def tcpudp(self):
        if self.ipv4 is None:
            return None
        is_tcpudp = (self.ipv4._raw.protocol == 6) | (self.ipv4._raw.protocol == 17)
        if utils.definitely_true(self._state.solver, is_tcpudp):
            return ValueProxy(self._state, TcpUdpHeader(
                src=self.data[36*8-1:34*8],
                dst=self.data[38*8-1:36*8]
            ))
        elif utils.definitely_false(self._state.solver, is_tcpudp):
            return None
        raise VerificationException("May or may not be TCP/UDP; this case isn't handled yet")


class SpecConfig:
    pass


class _SpecState: pass # just so we can add stuff to it

def create_angr_state(constraints): 
    state = _SpecState()

    # Angr plugins make some assumptions about structure
    state._get_weakref = lambda: state # not really a weakref; whatever
    state._global_condition = None
    state.arch = ArchAMD64()
    state.options = angr.options.symbolic
    state.supports_inspect = False

    state.memory = FractionalMemory(memory_id="mem")
    state.memory.set_state(state)

    state.solver = SimSolver()
    state.solver.set_state(state)
    state.solver.add(*constraints)

    # Common shortcuts we use
    state.add_constraints = state.solver.add
    state.satisfiable = state.solver.satisfiable

    return state
