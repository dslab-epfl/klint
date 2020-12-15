# Standard/External libraries
from abc import ABC, abstractmethod
from angr import SimState
import sys
import claripy
import re
import traceback

# Us
from verif.persistence import load_data, StateData
from verif.common import create_angr_state
from binary.ghost_maps import (RecordNew, RecordNewArray, RecordLength, RecordGet,
                               RecordSet, RecordRemove, RecordForall)
from binary.utils import definitely_true, definitely_false
import traces.helpers as helpers

# Typing
from typing import Set, Callable, Dict, List, Tuple

Record = object


FORALL_KEY: str = "KEY"
FORALL_VALUE: str = "VALUE"
FORALL_RESERVED: Set[str] = {FORALL_KEY, FORALL_VALUE}

class TraceProofException(Exception):
    pass


class Proof(object):

    # === Public API ===

    def __init__(self, name: str, state: StateData) -> None:
        self.name: str = name
        self.proof: List[str] = []
        self.state: SimState = create_angr_state(state.constraints)

        # ghost map name -> record that generated the ghostmap 
        self.ghost_maps: Dict[str, Record] = {}
        # symbol name -> symbol bitwidth
        self.symbols: Dict[str, int] = {}
        # fixpoint return value -> (fixpoint name, list of fixpoint's external variables)
        self.fixpoints: Dict[str, Tuple[str, List[str]]] = {}
        
        # Iterate over records and create the proof as we go
        for record in state.ghost_history:
            try:
                if type(record) in HANDLERS:
                    HANDLERS[type(record)](self, record)
                else:
                    pass
            except Exception:
                print(f"\n{record} failed to be parsed.")
                print(traceback.format_exc())
                sys.exit()

    def append_to_proof(self, *proof: List[str]) -> None:
        # for p in proof:
        #     print(f"\t{p}")
        self.proof.extend(proof)

    def add_symbol(self, symbol_name: str, bit_width: int) -> None:
        self.symbols[symbol_name] = bit_width
        self.append_to_proof(f"//@ list<bool> {symbol_name};")

    def write_to_file(self, filename: str):
        with open(filename, "a") as f:
            
            # Define all fixpoints used in ghostmap_forall invocations
            if len(self.fixpoints) > 0:
                f.write("/*@\n")
                for result, (name, external_vars) in self.fixpoints.items():
                    ext_params = f"list<bool> {', list<bool> '.join(external_vars)}," if len(external_vars) > 0 else ""
                    f.write(f"    fixpoint bool {name}({ext_params} list<bool> {FORALL_KEY}, list<bool> {FORALL_VALUE}) {{\n")
                    f.write(f"        return {result};\n")
                    f.write("    }\n")
                f.write("@*/\n")

            f.write(f"void {self.name}()\n")
            f.write("    //@ requires true;\n")
            f.write("    //@ ensures true;\n")
            f.write("{\n")
            [f.write(f"    {line}\n") for line in self.proof]
            f.write("    //@ assert (true);\n") # If there isn't an assert then VeriFast doesn't verify the trace
            f.write("}\n")

    def parse_fixpoint(self, conjunctions: List[claripy.ast.BV]) -> str:

        def collect_external_vars(bv: claripy.ast.BV) -> Set[str]:
            if bv.op == "BVS":
                if bv.args[0] not in FORALL_RESERVED:
                    return set([bv.args[0]])
                return set()
            elif bv.op == "Extract":
                return collect_external_vars(bv.args[2])
            else:
                acc: Set[str] = set()
                for arg in bv.args:
                    if (issubclass(type(arg), claripy.ast.BV)):
                        acc |= collect_external_vars(arg)
                return acc

        # Parse forall predicate
        forall_result: str = " && ".join(
            [self.parse_expression(conj) for conj in conjunctions])

        fixpoint_name: str = f"{self.name}_forall_fix_{len(self.fixpoints)}"
        external_vars: List[str] = []

        if forall_result in self.fixpoints:
            fixpoint_name, external_vars = self.fixpoints[forall_result]
        else:
            # Accumulate all external variables
            set_vars: Set[str] = set()
            for conj in conjunctions:
                set_vars |= collect_external_vars(conj)
            external_vars = list(set_vars)
            self.fixpoints[forall_result] = (fixpoint_name, external_vars)

        return f"({fixpoint_name})({', '.join(external_vars)})" if len(external_vars) > 0 else fixpoint_name

    def parse_expression(self, bv: claripy.ast.BV, as_scalar: bool = False) -> str:

        def add_symbol_if_not_exists(symbol: claripy.ast.BV) -> str:
            name: str = helpers.sanitize_name(symbol.args[0])
            if name not in self.symbols:
                if name in self.ghost_maps:
                    # Actually a ghostmap, replace token with previously created bitvector
                    name = f"addr_{name}"
                elif name not in FORALL_RESERVED:
                    self.add_symbol(name, helpers.get_bv_bit_width(name))
            return name

        expr: str = ""

        if bv.op == "BVV":
            if as_scalar:  # Avoid complexifying the VeriFast expression
                return str(bv.args[0])
            expr = f"snd(bits_of_int({bv.args[0]}, {helpers.nat_of_int(bv.length)}))"

        elif bv.op == "BVS":
            expr = add_symbol_if_not_exists(bv)

        elif bv.op == "Extract":
            slice_msb, slice_lsb, sliced_bv = bv.args
            name: str = add_symbol_if_not_exists(sliced_bv)
            expr = f"chunk({name}, {slice_lsb}, {slice_msb + 1})"

        elif bv.op == "Concat":
            subexprs: List[str] = [
                self.parse_expression(arg) for arg in bv.args]
            expr = subexprs[0]
            for sub in subexprs[1:]:
                expr = f"append({expr}, {sub})"

        elif bv.op == "LShR":
            shift: str = self.parse_expression(bv.args[1], as_scalar=True)
            zero_ext: str = f"repeat(false, nat_of_int({shift}))"
            expr = f"append({zero_ext}, drop({shift}, {self.parse_expression(bv.args[0])}))"

        elif bv.op == "ZeroExt":
            expr = f"append(repeat(false, {helpers.nat_of_int(bv.args[0])}), {self.parse_expression(bv.args[1])})"

        elif bv.op == "__add__":
            subexprs: List[str] = [self.parse_expression(
                arg, as_scalar=True) for arg in bv.args]
            expr = " + ".join(subexprs)
            if as_scalar:  # Avoid complexifying the VeriFast expression
                return expr
            expr = f"snd(bits_of_int({expr}, {helpers.nat_of_int(bv.length)}))"
        elif bv.op == "__lt__":
            expr = f"({self.parse_expression(bv.args[0], as_scalar=True)} < {self.parse_expression(bv.args[1], as_scalar=True)})"
        elif bv.op == "__eq__":
            expr = f"({self.parse_expression(bv.args[0])} == {self.parse_expression(bv.args[1])})"
        elif bv.op == "__ne__":
            expr = f"({self.parse_expression(bv.args[0])} != {self.parse_expression(bv.args[1])})"
        else:
            raise TraceProofException(f"Unknown operator {bv.op}.")

        return f"int_of_bits(0, {expr})" if as_scalar else expr

    # === Protected API ===

    def _handle_record_new(self, record: RecordNew) -> None:
        result: str = helpers.extract_name(record.result)
        self.ghost_maps[result] = record
        self.append_to_proof(
            f"//@ list<pair<list<bool>, list<bool> > > {result};")

    def _handle_record_new_array(self, record: RecordNewArray) -> None:
        result: str = helpers.extract_name(record.result)
        self.ghost_maps[result] = record
        self.append_to_proof(
            f"//@ list<pair<list<bool>, list<bool> > > {result};")

        # Ghostmaps which represent a simple memory location might be used down the line inside expressions as a memory address
        # We create a bitvector to represent this address
        if record.length.args[0] == 1:
            self.append_to_proof(f"//@ list<bool> addr_{result};")

    def _handle_record_length(self, record: RecordLength) -> None:
        ghostmap: str = helpers.extract_name(record.obj)
        length_expr: str = self.parse_expression(record.result)
        self.append_to_proof(
            f"//@ assume (length({ghostmap}) == {length_expr});")

    def _handle_record_get(self, record: RecordGet) -> None:
        ghostmap: str = helpers.extract_name(record.obj)
        present: claripy.ast.BV = record.result[1]
        key_expr: str = self.parse_expression(record.key)
        result_expr: str = self.parse_expression(record.result[0])
        if definitely_true(self.state.solver, present):
            self.append_to_proof(
                f"//@ assume (ghostmap_get({ghostmap}, {key_expr}) == some({result_expr}));")
        elif definitely_false(self.state.solver, present):
            self.append_to_proof(
                f"//@ assume (ghostmap_get({ghostmap}, {key_expr}) == none);")
        else:
            raise TraceProofException(
                "What do we do here ? Is this even possible ?")

    def _handle_record_set(self, record: RecordSet) -> None:
        ghostmap: str = helpers.extract_name(record.obj)
        key_expr: str = self.parse_expression(record.key)
        value_expr: str = self.parse_expression(record.value)
        self.append_to_proof(
            f"//@ ghostmap_set({ghostmap}, {key_expr}, {value_expr});")

    def _handle_record_remove(self, record: RecordRemove) -> None:
        ghostmap: str = helpers.extract_name(record.obj)
        key_expr: str = self.parse_expression(record.key)
        self.append_to_proof(f"//@ ghostmap_remove({ghostmap}, {key_expr});")

    def _handle_record_forall(self, record: RecordForall) -> None:
        ghostmap: str = helpers.extract_name(record.obj)
        fixpoint = self.parse_fixpoint(record.pred.expr.args[1:])
        if definitely_true(self.state.solver, record.result):
            self.append_to_proof(
                f"//@ assume (true == ghostmap_forall({ghostmap}, {fixpoint}));")
        elif definitely_false(self.state.solver, record.result):
            self.append_to_proof(
                f"//@ assume (false == ghostmap_forall({ghostmap}, {fixpoint}));")
        else:
            raise TraceProofException(
                "What do we do here ? Is this even possible ?")


HANDLERS: Dict[object, Callable[[Proof, Record, StateData], None]] = {
    RecordNew: Proof._handle_record_new,
    RecordNewArray: Proof._handle_record_new_array,
    RecordLength: Proof._handle_record_length,
    RecordGet: Proof._handle_record_get,
    RecordSet: Proof._handle_record_set,
    RecordRemove: Proof._handle_record_remove,
    RecordForall: Proof._handle_record_forall,
}


def generate_traces(nf_data_path: str, output_file: str) -> None:
    nf_data: List[StateData] = load_data(nf_data_path)
    with open(output_file, "w") as f:
        # VeriFast includes
        f.write("//@ #include \"proof/ghost_map.gh\"\n")
        f.write("//@ #include \"bitops.gh\"\n")
        f.write("//@ #include \"nat.gh\"\n")
        f.write("//@ #include \"listutils.gh\"\n\n")

    for (i, state_data) in enumerate(nf_data):
        p: Proof = Proof(f"trace{i}", state_data)
        p.write_to_file(output_file)
