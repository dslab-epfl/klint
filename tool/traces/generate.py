# Standard/External libraries
from abc import ABC, abstractmethod
from angr import SimState
import sys
import claripy
import re

# Us
from verif.persistence import load_data, StateData
from verif.common import create_angr_state
from binary.ghost_maps import (RecordNew, RecordNewArray, RecordLength, RecordGet,
                               RecordSet, RecordRemove, RecordForall)
from binary.utils import definitely_true, definitely_false
import traces.helpers as helpers

# Typing
from typing import Callable, Dict, List, Tuple

Record = object


class TraceProofException(Exception):
    pass


class ProofBuilder(object):

    # === Public API ===

    def __init__(self, state: StateData) -> None:
        self.proof: List[str] = []
        self.ghost_maps: Dict[str, Record] = {}
        self.symbols: Dict[str, int] = {}
        self.state: SimState = create_angr_state(state.constraints)
        print(state.constraints)

        # Iterate over records and create the proof as we go
        for record in state.ghost_history:
            if type(record) in HANDLERS:
                # print(record)
                HANDLERS[type(record)](self, record)
            else:
                pass
                # print(f"IGNORED: {record}")

    def append_to_proof(self, *proof: List[str]) -> None:
        for p in proof:
            print(f"\t{p}")
        self.proof.extend(proof)

    def add_symbol(self, symbol_name: str, bit_width: int) -> None:
        self.symbols[symbol_name] = bit_width
        self.append_to_proof(f"//@ list<bool> {symbol_name};")

    def parse_expression(self, bv: claripy.BV) -> str:
        splitted: List[str] = str(bv)[1:-1].split(" ")
        final_bit_width: int = int(splitted[0][2:])
        tokens: List[str] = splitted[1:]

        # Parse operands
        operands: List[OperandToken] = []
        for i in range(0, len(tokens), 2):
            t = tokens[i]
            if SCALAR_PATTERN_DEC.match(t):
                operands.append(ScalarToken(int(t)))
            elif SCALAR_PATTERN_HEX.match(t):
                operands.append(ScalarToken(int(t, 16)))
            elif BV_SLICE_PATTERN.match(t):
                operands.append(BVSliceToken(t))
            elif BV_PATTERN.match(t):
                operands.append(BVToken(t))
            else:
                raise TraceProofException(f"Can't parse symbol {t}.")

        # Parse operators
        operators: List[OperatorToken] = []
        for i in range(1, len(tokens), 2):
            t = tokens[i]
            if t == CONCAT:
                operators.append(ConcatToken())
            elif t == ADD:
                operators.append(AddToken())
            elif t == SUBTRACT:
                operators.append(SubtractToken())
            else:
                raise TraceProofException(f"Can't parse operator {t}.")

        # Declare VeriFast variables for all new operands that are symbols
        for opand in operands:
            if issubclass(type(opand), OperandTokenSymbol):
                if opand.name not in self.symbols:
                    if opand.name in self.ghost_maps:
                        # Actually a ghostmap, replace token with previously created bitvector
                        opand.name = f"addr_{opand.name}"
                    else:
                        self.add_symbol(opand.name, opand.bit_width)

        # === Create equivalent VeriFast expression ===

        # First operand must always be a symbol
        if not issubclass(type(operands[0]), OperandTokenSymbol):
            if len(operands) == 1 and issubclass(type(operands[0]), ScalarToken):
                return f"snd(bits_of_int({operands[0].value}, {helpers.nat_of_int(final_bit_width)}))"
            else:
                raise TraceProofException(
                    f"Incorrect type for {operands[0]}: expected subclass of {OperandTokenSymbol}")

        # Iteratively construct the expression
        expr: str = operands[0].to_verifast_syntax()
        acc_bit_width: int = operands[0].bit_width
        for i in range(0, len(operators)):
            expr, acc_bit_width = operators[i].to_verifast_syntax(
                expr, operands[i + 1], acc_bit_width)

        if acc_bit_width != final_bit_width:
            raise TraceProofException(
                f"Expected symbol of length {final_bit_width}, but got {acc_bit_width}")

        return expr

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
        pass

    def _handle_record_get(self, record: RecordGet) -> None:
        ghostmap: str = helpers.extract_name(record.obj)
        present: claripy.BV = record.result[1]
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
        pass


HANDLERS: Dict[object, Callable[[ProofBuilder, Record, StateData], None]] = {
    RecordNew: ProofBuilder._handle_record_new,
    RecordNewArray: ProofBuilder._handle_record_new_array,
    RecordLength: ProofBuilder._handle_record_length,
    RecordGet: ProofBuilder._handle_record_get,
    RecordSet: ProofBuilder._handle_record_set,
    RecordRemove: ProofBuilder._handle_record_remove,
    RecordForall: ProofBuilder._handle_record_forall,
}

BV_SLICE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*\[[0-9]+:[0-9]+\]$")
BV_PATTERN = re.compile(r"^[A-Za-z]")
SCALAR_PATTERN_DEC = re.compile(r"^[0-9]+$")
SCALAR_PATTERN_HEX = re.compile(r"^0x[0-9a-f]+$")

CONCAT = ".."
ADD = "+"
SUBTRACT = "-"

# === TOKENS FOR PARSING ===


class Token(ABC):
    pass

# --- OPERANDS ---


class OperandToken(Token):
    @abstractmethod
    def to_verifast_syntax(self) -> str:
        pass


class OperandTokenSymbol(OperandToken):
    def __init__(self, name: str) -> None:
        self.name: str = helpers.sanitize_name(name)
        self.bit_width: int = int(name[name.rfind("_") + 1:])


class BVToken(OperandTokenSymbol):
    def __init__(self, name: str) -> None:
        super().__init__(name)

    def to_verifast_syntax(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"<BV{self.bit_width} {self.name}>"


class BVSliceToken(OperandTokenSymbol):
    def __init__(self, name: str) -> None:
        # Parse the name to determine slice indices
        index_slice = name.rfind("[")
        slice_info = name[index_slice:]
        index_slice_split = slice_info.find(":")

        super().__init__(name[:index_slice])
        self.slice_lsb: int = int(slice_info[index_slice_split+1:-1])
        self.slice_msb: int = int(slice_info[1:index_slice_split])
        self.bit_width = self.slice_msb - self.slice_lsb + 1

    def to_verifast_syntax(self) -> str:
        return f"chunk({self.name}, {self.slice_lsb}, {self.slice_msb + 1})"

    def __repr__(self) -> str:
        return f"<BVSlice{self.bit_width} {self.name}[{self.slice_lsb}:{self.slice_msb}]>"


class ScalarToken(OperandToken):
    def __init__(self, value: int) -> None:
        self.value: int = value

    def to_verifast_syntax(self) -> str:
        return hex(self.value)

    def __repr__(self) -> str:
        return f"<Scalar {self.value}>"

# --- OPERATORS ---


class OperatorToken(ABC):
    @abstractmethod
    def to_verifast_syntax(self, op_left: str, op_right: OperandToken, acc_bit_width: int) -> Tuple[str, int]:
        pass


class ConcatToken(OperatorToken):
    def to_verifast_syntax(self, op_left: str, op_right: OperandToken, acc_bit_width: int) -> Tuple[str, int]:
        if not issubclass(type(op_right), OperandTokenSymbol):
            raise TraceProofException(
                f"Incorrect type for {op_right}: expected subclass of {OperandTokenSymbol}")
        return (f"append({op_left}, {op_right.to_verifast_syntax()})", acc_bit_width + op_right.bit_width)

    def __repr__(self) -> str:
        return ".."


class AddToken(OperatorToken):
    def to_verifast_syntax(self, op_left: str, op_right: OperandToken, acc_bit_width: int) -> Tuple[str, int]:
        if not issubclass(type(op_right), ScalarToken):
            raise TraceProofException(
                f"Incorrect type for {op_right}: expected subclass of {ScalarToken}")
        return (f"snd(bits_of_int(int_of_bits(0, {op_left}) + {op_right.to_verifast_syntax()}, {helpers.nat_of_int(acc_bit_width)}))",
                acc_bit_width)

    def __repr__(self) -> str:
        return "+"


class SubtractToken(OperatorToken):
    def to_verifast_syntax(self, op_left: str, op_right: OperandToken, acc_bit_width: int) -> Tuple[str, int]:
        if not issubclass(type(op_right), ScalarToken):
            raise TraceProofException(
                f"Incorrect type for {op_right}: expected subclass of {ScalarToken}")
        return (f"snd(bits_of_int(int_of_bits(0, {op_left}) - {op_right.to_verifast_syntax()}, {helpers.nat_of_int(acc_bit_width)}))",
                acc_bit_width)

    def __repr__(self) -> str:
        return "-"


def generate_traces(nf_data_path: str) -> None:
    nf_data: List[StateData] = load_data(nf_data_path)
    for state_data in nf_data[len(nf_data) - 1:]:
        _: ProofBuilder = ProofBuilder(state_data)
        print("------------------------")
