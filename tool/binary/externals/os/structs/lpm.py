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

class LpmAlloc(angr.SimProcedure):
    def run(self):
        print(f"!!! lpm_alloc")

        # Postconditions
        result = self.state.memory.allocate_opaque("lpm")
        table = self.state.maps.new(IP_LEN + bitsizes.uint8_t, bitsizes.uint16_t, name="lpm_table")
        self.state.metadata.set(result, Lpm(table))
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
    def run(self, lpm, prefix, out_value, out_prefix, out_prefixlen):
        # Casts
        lpm = cast.ptr(lpm)
        prefix = cast.uint32_t(prefix)
        out_value = cast.ptr(out_value)
        out_prefix = cast.ptr(out_prefix)
        out_prefixlen = cast.ptr(out_prefixlen)
        print(  f"!!! lpm_lookup_elem [lpm: {lpm}, prefix: {prefix}, " +
                f"out_value: {out_value}, out_prefix: {out_prefix}, out_prefixlen: {out_prefixlen}]")

        # Symbolism assumptions
        if out_value.symbolic or out_prefix.symbolic or out_prefixlen.symbolic:
            raise SymbexException("Out parameters cannot be symbolic")

        # Postconditions
        lpmp = self.state.metadata.get(Lpm, lpm)
        out_value_bv = claripy.BVS("out_value", bitsizes.uint16_t)
        out_prefix_bv = claripy.BVS("out_prefix", IP_LEN)
        out_prefixlen_bv = claripy.BVS("out_prefixlen", bitsizes.uint8_t)
        self.state.memory.store(out_value, out_value_bv, endness=self.state.arch.memory_endness)
        self.state.memory.store(out_prefix, out_prefix_bv, endness=self.state.arch.memory_endness)
        self.state.memory.store(out_prefixlen, out_prefixlen_bv, endness=self.state.arch.memory_endness)

        def forall_fun(key, value):
            key_prefix = key[39:8]
            key_prefixlen = key[7:0]
            # For each entry in the map, either:
            # the entry's prefix length is shorter (=> lower priority), or
            shorter_prefix = key_prefixlen < out_prefixlen_bv
            # the prefixes don't match (=> no match), or
            no_match = claripy.LShR(key_prefix, IP_LEN - key_prefixlen) != claripy.LShR(out_prefix_bv, IP_LEN - out_prefixlen_bv)
            # the entry corresponds to the returned value (=> match)
            match = (key == out_prefix_bv.concat(out_prefixlen_bv))
            return shorter_prefix | no_match | match
        utils.add_constraints_and_check_sat(self.state, self.state.maps.forall(lpmp.table, forall_fun))

        def case_has(state, value):
            print("!!! lpm_lookup_elem: lookup success")
            return claripy.BVV(1, bitsizes.bool)
        def case_not(state):
            print("!!! lpm_lookup_elem: lookup fail")
            return claripy.BVV(0, bitsizes.bool)

        return utils.fork_guarded_has(self, lpmp.table, out_prefix_bv.concat(out_prefixlen_bv), case_has, case_not)
