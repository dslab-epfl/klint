from collections.abc import Callable, Iterable
from typing import Any, Generic, TypeVar

from angr.sim_state import SimState

from .persistence import StateData
from .spec_prefix import _spec_wrapper
from .symbex_data import SymbexData, get_symbex, set_symbex
from .value_proxy import ValueProxy

"""
The original peer symbex approach from https://hoheinzollern.files.wordpress.com/2008/04/seer1.pdf works for exhaustive symbex of all boolean conditions.
We extend it to support an 'or' combination for any value, so that one can say symbex succeeds if any one of a given set of choices succeeds.
This provides a form of existential quantification to the code under symbex, similar to https://www.usenix.org/conference/hotos13/session/bugnion

The code under verification can call the '__choose__(choices)' function, which returns a choice, to use existential quantification.
"""

def _symbex_one(state, func, branches: list[tuple[Any, bool]], choices: list[Any]) -> tuple[list[tuple[Any, bool]], list[Any]]:
    symbex = SymbexData()
    symbex.branches = branches
    symbex.choices = choices
    symbex.state = ValueProxy.wrap(state.copy())
    set_symbex(symbex)
    func()
    symbex = get_symbex()
    return symbex.branches, symbex.choices

def _symbex(state_data: Iterable[tuple[SimState, Callable[[], None]]]) -> tuple[list[Any], list[Any]]:
    choices = []
    while True:
        try:
            results = []
            for (state, func) in state_data:
                state_results = []
                branches = []
                while True:
                    (branches, choices) = _symbex_one(state, func, branches, choices)
                    # Path succeeded
                    state_results.append([f if b else ~f for (f, b) in branches])
                    # Prune branches that were fully explored
                    while len(branches) > 0 and not branches[-1][1]: branches.pop()
                    # If all branches were fully explored, we're done with this state!
                    if len(branches) == 0:
                        results.append(state_results)
                        break
                    # Otherwise, flip the last branch
                    branches[-1] = (branches[-1][0], False)
            # If we reached the end of the loop, we're all done!
            return ([cs[0] for cs in choices], results)
        except Exception as ex:
            # Just throw for built-in exceptions, e.g., syntax errors
            if ex.__class__.__module__ == 'builtins':
                raise
            # Debug:
            print("A choice didn't work. Trying with a different one.")
            # Prune choice sets that were fully explored
            while len(choices) > 0 and len(choices[-1]) == 1: choices.pop()
            # If all choices were explored, we failed
            if len(choices) == 0: raise
            # Otherwise, change the last choice
            choices[-1].pop(0)

def symbex(spec: Callable[..., None], state_data):
    # locals have to be the same as globals, otherwise Python encapsulates the program in a class and then one can't use classes inside it...
    return _symbex([(
        state,
        lambda args=args: _spec_wrapper(ValueProxy.wrap(spec), ValueProxy.wrap(args))
    ) for (state, args) in state_data])
