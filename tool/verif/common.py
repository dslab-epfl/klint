import angr
from angr.state_plugins.solver import SimSolver
from archinfo.arch_amd64 import ArchAMD64
import claripy

from .defs import *
from binary import bitsizes
from binary import utils
from binary.memory_fractional import FractionalMemory


class VerificationException(Exception): pass


# TODO: Then do the bridge, try to get the Polycube one to verify + the Vigor one if possible
#       And maybe just make up something for the policer...

class ValueProxy:
    @staticmethod
    def extract(value, type=None):
        result = value._value
        if type is None:
            return result
        else:
            size = type_size(type) * 8 # TODO in general need to figure out whether having type_size be in bits would be easier...
            assert size >= result.size(), "the actual type should have a size at least that of the result's"
            return result.zero_extend(size - result.size())

    def __init__(self, state, value, type=None):
        assert value is not None
        assert not isinstance(value, ValueProxy)
        self._state = state
        self._value = value
        self._type = type
        if self._type is not None:
            size = type_size(self._type)
            assert size <= self._value.size(), "the actual type should have a size at most that of the result's"
            if size < self._value.size():
                self._value = self._value[size-1:0]

    def __getattr__(self, name):
        if name == "_raw":
            return self._value

        if name[0] == "_":
            return super().__getattr__(name, value)

        if isinstance(self._type, dict):
            if name in self._type:
                offset = 0
                for (k, v) in self._type.items(): # Python preserves insertion order from 3.7 (3.6 for CPython)
                    if k == name:
                        return ValueProxy(self._state, self._value[(type_size(v)+offset)*8-1:offset*8], type=v)
                    offset = offset + type_size(v)

        # Do not expose Claripy attrs such as "length"
        if not isinstance(self._value, claripy.ast.Base) and hasattr(self._value, name):
            return ValueProxy(self._state, getattr(self._value, name))

        raise VerificationException(f"idk what to do about attr '{name}'")

    def __setattr__(self, name, value):
        if name[0] == "_":
            return super().__setattr__(name, value)
        raise "TODO"

    def __repr__(self):
        return self._value.__repr__()

    def _op(self, other, op):
        if isinstance(self._type, dict):
            raise VerificationException("Cannot perform ops on a composite type")

        other_value = other
        self_value = self._value

        # Convert if needed
        if isinstance(other, ValueProxy):
            other_value = other._value
        if isinstance(other_value, float) and other_value == other_value // 1:
            other_value = int(other_value)
        if not isinstance(other_value, claripy.ast.Base):
            if isinstance(other_value, int):
                other_value = claripy.BVV(other_value, max(8, self_value.size())) # 8 bits minimum

        if isinstance(self_value, claripy.ast.BV):
            self_value = self_value.zero_extend(max(0, other_value.size() - self_value.size()))
            other_value = other_value.zero_extend(max(0, self_value.size() - other_value.size()))

        return ValueProxy(self._state, getattr(self_value, op)(other_value))


    def __bool__(self):
        result = utils.get_if_constant(self._state.solver, self._value)
        if result is None:
            raise VerificationException("Could not prove: " + str(self._value))
        return result


    def __invert__(self):
        return ValueProxy(self._state, ~self._value)
    
    def __and__(self, other):
        return self._op(other, "__and__")
    def __rand__(self, other):
        return self._op(other, "__and__")
    
    def __or__(self, other):
        return self._op(other, "__or__")
    def __ror__(self, other):
        return self._op(other, "__or__")

    def __eq__(self, other):
        return self._op(other, "__eq__")

    def __ne__(self, other):
        return self._op(other, "__ne__")

    def __lt__(self, other):
        return self._op(other, "__lt__") # TODO: signedness of {L/G}{E/T} and rshift

    def __le__(self, other):
        return self._op(other, "__le__")

    def __gt__(self, other):
        return self._op(other, "__gt__")

    def __ge__(self, other):
        return self._op(other, "__ge__")
    
    def __mul__(self, other):
        return self._op(other, "__mul__")
    def __rmul__(self, other):
        return self._op(other, "__mul__")
    
    def __rshift__(self, other):
        return self._op(other, "LShR")
    def __rrshift__(self, other):
        return self._op(other, "LShR")
    
    def __lshift__(self, other):
        return self._op(other, "__lshift__")
    def __rlshift__(self, other):
        return self._op(other, "__lshift__")


def type_size(type):
    if isinstance(type, int):
        return type // 8
    if isinstance(type, str):
        return getattr(bitsizes, type) // 8
    if isinstance(type, dict):
        return sum([type_size(v) for v in type.values()])
    raise VerificationException(f"idk what to do with type '{type}'")


class SpecFloodedDevice:
    def __init__(self, state, orig_device):
        self._state = state
        self._orig_device = orig_device

    def __contains__(self, item):
        return ValueProxy(self._state, ValueProxy.extract(item) != self._orig_device)

class SpecSingleDevice:
    def __init__(self, state, device):
        self._state = state
        self._device = device

    def __contains__(self, item):
        return ValueProxy(self._state, ValueProxy.extract(item) == self._device)

class SpecPacket:
    def __init__(self, state, data, length, devices):
        self._state = state
        self.data = data # TODO should be accessible by specs, though we don't need it for now
        self.length = ValueProxy(self._state, length)
        self._devices = devices

    @property
    def device(self):
        if isinstance(self._devices, SpecSingleDevice):
            return ValueProxy(self._state, self._devices._device)
        raise VerificationException("The packet was sent on multiple devices")

    @property
    def devices(self):
        return self._devices

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
                checksum=self.data[start+12*8-1:start+10*8],
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
