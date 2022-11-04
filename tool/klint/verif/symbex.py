from collections.abc import Callable, Iterable
from typing import Any, Generic, TypeVar

from angr.sim_state import SimState
import claripy

from .persistence import StateData
from .value_proxy import ValueProxy
from .symbex_data import SymbexData, get_symbex, set_symbex

"""
The original peer symbex approach from https://hoheinzollern.files.wordpress.com/2008/04/seer1.pdf works for exhaustive symbex of all boolean conditions.
We extend it to support an 'or' combination for any value, so that one can say symbex succeeds if any one of a given set of choices succeeds.
This provides a form of existential quantification to the code under symbex, similar to https://www.usenix.org/conference/hotos13/session/bugnion

The code under verification can call the '__choose__(choices)' function, which returns a choice, to use existential quantification.
"""

# TODO: The 'choices' logic makes too many assumptions without checking them;
#       we need to make sure the requested choices are the same in all paths

def symbex_builtin_choose(choices):
    assert isinstance(choices, list)
    assert len(choices) != 0
    symbex = get_symbex()
    if symbex.choice_index == len(symbex.choices):
        symbex.choices.append(choices)
    else:
        assert [a is b for (a,b) in zip(choices, symbex.choices[symbex.choice_index])], "choices must be the same across all paths"
    # Exclude those we have used already
    while any(cs[0] is symbex.choices[symbex.choice_index][0] for cs in symbex.choices[:symbex.choice_index]):
        print("Dismissing dupe", symbex.choices[symbex.choice_index][0])
        symbex.choices[symbex.choice_index].pop(0)
    result = symbex.choices[symbex.choice_index][0]
    symbex.choice_index = symbex.choice_index + 1
    set_symbex(symbex)
    return result

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

def symbex(program, func_name, globs, state_data):
    set_symbex(SymbexData())
    globs['__choose__'] = ValueProxy.wrap(symbex_builtin_choose)
    # locals have to be the same as globals, otherwise Python encapsulates the program in a class and then one can't use classes inside it...
    exec(program, globs, globs)

    return _symbex([(
        state,
        lambda args=args: globs[func_name](*[ValueProxy.wrap(arg) for arg in args])
    ) for (state, args) in state_data])
