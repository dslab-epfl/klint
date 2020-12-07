# Standard/External libraries
import claripy

# Typing
from typing import Dict

def nat_of_int(value: int) -> str:
    return __NAT[value] if value in __NAT else f"nat_of_int({value})"

def extract_name(bv: claripy.BV) -> str:
    return sanitize_name(str(bv)[1:-1].split(" ")[1])

def sanitize_name(name: str) -> str:
    return name.replace("[", "_").replace("]", "_").replace("-", "_")

def get_bv_bit_width(name: str) -> int:
    return int(name[name.rfind("_") + 1:])

__NAT: Dict[int, str] = {
    8: "N8",
    16: "N16",
    32: "N32",
    64: "N64",
}