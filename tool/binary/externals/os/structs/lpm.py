# Standard/External libraries
import angr
import claripy
from collections import namedtuple

# Us
from .pool import Pool
import binary.bitsizes as bitsizes
import binary.cast as cast
import binary.clock as clock
import binary.utils as utils
from binary.exceptions import SymbexException

Lpm = namedtuple("lpmp", ["table"])

def bit_not(n, numbits):
    return (1 << numbits) - 1 - n

IP_LEN = bitsizes.uint32_t

class LpmAlloc(angr.SimProcedure):
    def run(self):
        print(f"!!! lpm_alloc")

        # Postconditions
        result = self.state.memory.allocate_opaque("lpm")
        table = self.state.maps.new(IP_LEN + bitsizes.uint8_t, IP_LEN + bitsizes.uint16_t, name="lpm_table")
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
        # Mask for the "prefixlen" MSBs of prefix
        mask = claripy.BVV(bit_not(((1 << (IP_LEN - prefixlen.args[0])) - 1), IP_LEN), IP_LEN)
        self.state.maps.set(lpmp.table, prefix.concat(prefixlen), mask.concat(value))
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

        def case_true(state):
            print("!!! lpm_lookup_elem: lookup success")
            # The function returns the longest prefix match
            def forall_fun(key, value):
                key_prefix = key[39:8]
                key_prefixlen = key[7:0]
                mask = value[47:16]

                # For each entry in the map, either:
                # shorter_prefix: the entry's prefix length is shorter
                # match: the entry corresponds to the returned values (out parameters)
                # no_match: the entry's prefix length is >= to the returned match but the prefixes don't match
                shorter_prefix = key_prefixlen < out_prefixlen_bv
                match = claripy.And(key == out_prefix_bv.concat(out_prefixlen_bv), (prefix & mask) == (key_prefix & mask))
                no_match = claripy.And(key_prefixlen >= out_prefixlen_bv, (prefix & mask) != (key_prefix & mask))
                return claripy.Or(shorter_prefix, match, no_match)

            utils.add_constraints_and_check_sat(state, state.maps.forall(lpmp.table, forall_fun))
            return claripy.BVV(1, bitsizes.bool)
        def case_false(state):
            print("!!! lpm_lookup_elem: lookup fail")
            # There was no match
            def forall_fun(key, value):
                mask = value[47:16]
                return (prefix & mask) != (key[39:8] & mask)

            utils.add_constraints_and_check_sat(state, state.maps.forall(lpmp.table, forall_fun))
            return claripy.BVV(0, bitsizes.bool)

        get_value = self.state.maps.get(lpmp.table, out_prefix_bv.concat(out_prefixlen_bv))
        guard = claripy.And(get_value[1], get_value[0][15:0] == out_value_bv)
        return utils.fork_guarded(self, guard, case_true, case_false)
