# Standard/External libraries
import angr
import claripy
from collections import namedtuple

# Us
import binary.bitsizes as bitsizes
import binary.cast as cast
import binary.utils as utils
from binary.exceptions import SymbexException

Lpm = namedtuple("lpmp", ["table"])

IP_LEN = bitsizes.uint32_t

# TODO: Split allocation and fill-from-config
class LpmAlloc(angr.SimProcedure):
    def run(self):

        # Postconditions
        result = self.state.memory.allocate_opaque("lpm")
        table = self.state.maps.new(IP_LEN + bitsizes.uint8_t, bitsizes.uint16_t, "lpm_table")
        self.state.maps.havoc(table, self.state.symbol_factory.BVS("lpm_table_length", 64), False)
        self.state.metadata.set(result, Lpm(table))
        print(f"!!! lpm_alloc -> {result}")
        return result

class LpmUpdateElem(angr.SimProcedure):
    def run(self, lpm, prefix, prefixlen, value):
        # Casts
        lpm = cast.ptr(lpm)
        prefix = cast.uint32_t(prefix)
        prefixlen = cast.uint8_t(prefixlen)
        value = cast.uint16_t(value)
        print(  f"!!! lpm_update_elem [lpm: {lpm}, prefix: {prefix}, " 
                f"prefixlen: {prefixlen}, value: {value}]")

        # Postconditions
        lpmp = self.state.metadata.get(Lpm, lpm)
        self.state.maps.set(lpmp.table, prefix.concat(prefixlen), value)
        return claripy.BVV(1, bitsizes.bool)

class LpmLookupElem(angr.SimProcedure):
    def run(self, lpm, key, out_value, out_prefix, out_prefixlen):
        # Casts
        lpm = cast.ptr(lpm)
        key = cast.uint32_t(key)
        out_value = cast.ptr(out_value)
        out_prefix = cast.ptr(out_prefix)
        out_prefixlen = cast.ptr(out_prefixlen)
        print(  f"!!! lpm_lookup_elem [lpm: {lpm}, key: {key}, " +
                f"out_value: {out_value}, out_prefix: {out_prefix}, out_prefixlen: {out_prefixlen}]")

        # Postconditions
        lpmp = self.state.metadata.get(Lpm, lpm)
        out_value_bv = self.state.symbol_factory.BVS("out_value", bitsizes.uint16_t)
        out_prefix_bv = self.state.symbol_factory.BVS("out_prefix", IP_LEN)
        out_prefixlen_bv = self.state.symbol_factory.BVS("out_prefixlen", bitsizes.uint8_t)
        self.state.memory.store(out_value, out_value_bv, endness=self.state.arch.memory_endness)
        self.state.memory.store(out_prefix, out_prefix_bv, endness=self.state.arch.memory_endness)
        self.state.memory.store(out_prefixlen, out_prefixlen_bv, endness=self.state.arch.memory_endness)

        def matches(route):
            prefix = route[39:8]
            length = route[7:0].zero_extend(24)
            return prefix.LShR(length) == key.LShR(length)
        
        def case_none(state):
            print("!!! lpm_lookup_elem: none")
            return claripy.BVV(0, bitsizes.bool)
        def case_some(state):
            print("!!! lpm_lookup_elem: some")
            (value, has) = state.maps.get(lpmp.table, out_prefix_bv.concat(out_prefixlen_bv))
            utils.add_constraints_and_check_sat(
                state,
                state.maps.forall(lpmp.table, lambda k, v: ~matches(k) | (k[7:0] <= out_prefixlen_bv)),
                has,
                value == out_value_bv,
                matches(out_prefix_bv.concat(out_prefixlen_bv))
            )
            return claripy.BVV(1, bitsizes.bool)

        return utils.fork_guarded(self, self.state.maps.forall(lpmp.table, lambda k, v: ~matches(k)), case_none, case_some)
