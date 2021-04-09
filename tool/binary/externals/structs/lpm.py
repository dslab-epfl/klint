import angr
import claripy
from collections import namedtuple

import binary.utils as utils

Lpm = namedtuple("lpmp", ["table"])

IP_LEN = 32

# TODO: Split allocation and fill-from-config
class LpmAlloc(angr.SimProcedure):
    def run(self):

        # Postconditions
        result = claripy.BVS("lpm", self.state.sizes.ptr)
        table = self.state.maps.new(IP_LEN + self.state.sizes.uint8_t, self.state.sizes.uint16_t, "lpm_table")
        self.state.maps.havoc(table, claripy.BVS("lpm_table_length", 64), False)
        self.state.metadata.append(result, Lpm(table))
        print(f"!!! lpm_alloc -> {result}")
        return result

class LpmUpdateElem(angr.SimProcedure):
    def run(self, lpm, prefix, prefixlen, value):
        # Casts
        lpm = self.state.casts.ptr(lpm)
        prefix = self.state.casts.uint32_t(prefix)
        prefixlen = self.state.casts.uint8_t(prefixlen)
        value = self.state.casts.uint16_t(value)
        print(  f"!!! lpm_update_elem [lpm: {lpm}, prefix: {prefix}, " 
                f"prefixlen: {prefixlen}, value: {value}]")

        # Postconditions
        lpmp = self.state.metadata.get(Lpm, lpm)
        self.state.maps.set(lpmp.table, prefix.concat(prefixlen), value)
        return claripy.BVV(1, self.state.sizes.bool)

# TODO: The issue right now is that there could be two routes (P,L) and (P',L) where (P >> L) == (P' >> L) but P != P'...
class LpmLookupElem(angr.SimProcedure):
    def run(self, lpm, key, out_value, out_prefix, out_prefixlen):
        # Casts
        lpm = self.state.casts.ptr(lpm)
        key = self.state.casts.uint32_t(key)
        out_value = self.state.casts.ptr(out_value)
        out_prefix = self.state.casts.ptr(out_prefix)
        out_prefixlen = self.state.casts.ptr(out_prefixlen)
        print(  f"!!! lpm_lookup_elem [lpm: {lpm}, key: {key}, " +
                f"out_value: {out_value}, out_prefix: {out_prefix}, out_prefixlen: {out_prefixlen}]")

        # Postconditions
        lpmp = self.state.metadata.get(Lpm, lpm)
        out_value_bv = claripy.BVS("out_value", self.state.sizes.uint16_t)
        out_prefix_bv = claripy.BVS("out_prefix", IP_LEN)
        out_prefixlen_bv = claripy.BVS("out_prefixlen", self.state.sizes.uint8_t)
        out_route = out_prefix_bv.concat(out_prefixlen_bv)
        self.state.memory.store(out_value, out_value_bv, endness=self.state.arch.memory_endness)
        self.state.memory.store(out_prefix, out_prefix_bv, endness=self.state.arch.memory_endness)
        self.state.memory.store(out_prefixlen, out_prefixlen_bv, endness=self.state.arch.memory_endness)

        def matches(route):
            prefix = route[39:8]
            length = route[7:0].zero_extend(24)
            return prefix.LShR(length) == key.LShR(length)
        
        def case_none(state):
            print("!!! lpm_lookup_elem: none")
            return claripy.BVV(0, self.state.sizes.bool)
        def case_some(state):
            print("!!! lpm_lookup_elem: some")
            (value, has) = state.maps.get(lpmp.table, out_route)
            state.solver.add(
                state.maps.forall(lpmp.table, lambda k, v: ~matches(k) | (k[7:0] < out_prefixlen_bv) | (v == out_value_bv)),
                has,
                value == out_value_bv,
                matches(out_route)
            )
            return claripy.BVV(1, self.state.sizes.bool)

        return utils.fork_guarded(self, self.state, self.state.maps.forall(lpmp.table, lambda k, v: ~matches(k)), case_none, case_some)
