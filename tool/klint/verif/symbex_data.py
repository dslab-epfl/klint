from typing import Any

# Container for symbex
class SymbexData:
    def __init__(self):
        # list of (formula, bool) tuples, where the formula is the branch condition and the bool is its assignment for the path
        self.branches: list[tuple[Any, bool]] = list()
        # the index in `__branches__`
        self.branch_index = 0
        # list of lists, where the first item is the one that is used and the remaining are the alternatives
        self.choices: list[Any] = list()
        # the index in `__choices__`
        self.choice_index = 0
        # the current state
        self.state: Any = None
        # Both branches and choices can be pre-populated to force a specific path prefix, and will contain the entirety of the path at the end


# TODO avoid singleton

__symbex = SymbexData()


def get_symbex() -> SymbexData:
    return __symbex


def set_symbex(v: SymbexData) -> None:
    global __symbex
    __symbex = v
