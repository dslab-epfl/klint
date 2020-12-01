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
        table = self.state.maps.new(IP_LEN + bitsizes.uint8_t, bitsizes.uint16_t, name="lpm_table")
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

        # Symbolism assumptions
        if out_value.symbolic or out_prefix.symbolic or out_prefixlen.symbolic:
            raise SymbexException("Out parameters cannot be symbolic")

        # Postconditions
        lpmp = self.state.metadata.get(Lpm, lpm)
        out_value_bv = self.state.symbol_factory.BVS("out_value", bitsizes.uint16_t)
        out_prefix_bv = self.state.symbol_factory.BVS("out_prefix", IP_LEN)
        out_prefixlen_bv = self.state.symbol_factory.BVS("out_prefixlen", bitsizes.uint8_t)
        self.state.memory.store(out_value, out_value_bv, endness=self.state.arch.memory_endness)
        self.state.memory.store(out_prefix, out_prefix_bv, endness=self.state.arch.memory_endness)
        self.state.memory.store(out_prefixlen, out_prefixlen_bv, endness=self.state.arch.memory_endness)

        def forall_fun(k, v):
            k_prefix = k[39:8]
            k_prefixlen = k[7:0]
            # For each entry in the map, either:
            # the entry's prefix length is shorter (=> lower priority), or
            shorter_prefix = k_prefixlen < out_prefixlen_bv
            # the entry's prefix does not match the input key (=> no match), or
            no_match = claripy.LShR(k_prefix, (IP_LEN - k_prefixlen).zero_extend(24)) != claripy.LShR(key, (IP_LEN - k_prefixlen).zero_extend(24))
            # the entry corresponds to the returned value (=> match)
            match = (k == out_prefix_bv.concat(out_prefixlen_bv))
            return shorter_prefix | no_match | match
        utils.add_constraints_and_check_sat(self.state, self.state.maps.forall(lpmp.table, forall_fun))

        def case_has(state, value):
            print("!!! lpm_lookup_elem: lookup success")
            return claripy.BVV(1, bitsizes.bool)
        def case_not(state):
            print("!!! lpm_lookup_elem: lookup fail")
            return claripy.BVV(0, bitsizes.bool)

        return utils.fork_guarded_has(self, lpmp.table, out_prefix_bv.concat(out_prefixlen_bv), case_has, case_not)
