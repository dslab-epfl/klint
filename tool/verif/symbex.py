import claripy

"""
The original peer symbex approach from https://hoheinzollern.files.wordpress.com/2008/04/seer1.pdf works for exhaustive symbex of all boolean conditions.
We extend it to support an 'or' combination for any value, so that one can say symbex succeeds if any one of a given set of choices succeeds.
This provides a form of existential quantification to the code under symbex, similar to https://www.usenix.org/conference/hotos13/session/bugnion

The code under verification can call the '__choose__(choices)' function, which returns a choice, to use existential quantification.
"""

# Container for symbex
class _SymbexData:
    def __init__(self):
        # list of (formula, bool) tuples, where the formula is the branch condition and the bool is its assignment for the path
        self.branches = None
        # the index in `__branches__`
        self.branch_index = 0
        # list of lists, where the first item is the one that is used and the remaining are the alternatives
        self.choices = None
        # the index in `__choices__`
        self.choice_index = 0
        # the current state
        self.state = None
        # the previous state
        self.prev_state = None
        # Both branches and choices can be pre-populated to force a specific path prefix, and will contain the entirety of the path at the end


def symbex_builtin_choose(choices):
    global __symbex__
    if __symbex__.choice_index == len(__symbex__.choices):
        __symbex__.choices.append(choices)
    result = __symbex__.choices[__symbex__.choice_index][0]
    __symbex__.choice_index = __symbex__.choice_index + 1
    return result
    

class ValueProxy:
    @staticmethod
    def unwrap(value):
        if not isinstance(value, ValueProxy):
            return value
        return value._value

    @staticmethod
    def wrap_func(func):
        return lambda *args, **kwargs: ValueProxy(func(*[ValueProxy.unwrap(arg) for arg in args], **{k: ValueProxy.unwrap(v) for (k, v) in kwargs.items()}))

    def __init__(self, value):
        assert value is not None and value is not NotImplemented and not isinstance(value, ValueProxy), "value should make sense"
        self._value = value

    def __getattr__(self, name):
        if name[0] == "_":
            # Private members, for use within the class itself
            return super().__getattr__(name, value)

        if hasattr(self._value, name):
            if callable(getattr(self._value, name)):
                return ValueProxy.wrap_func(getattr(self._value, name))
            return ValueProxy(getattr(self._value, name))

        raise Exception(f"idk what to do about attr '{name}'")

    def __setattr__(self, name, value):
        assert name[0] == "_", "can only set private variables, which should be from within the class itself"
        return super().__setattr__(name, value)
    
    def __str__(self):
        return self._value.__str__()

    def __repr__(self):
        return self._value.__repr__()

    def _op(self, other, op):
        other_value = other
        self_value = self._value

        # Convert if needed
        if isinstance(other, ValueProxy):
            other_value = other._value
        if isinstance(other_value, float) and other_value == other_value // 1:
            other_value = int(other_value)
        if isinstance(other_value, int):
            if not isinstance(self_value, int):
                assert isinstance(self_value, claripy.ast.BV), "what else could it be?"
                other_value = claripy.BVV(other_value, max(8, self_value.size())) # 8 bits minimum

        if isinstance(self_value, claripy.ast.BV):
            self_value = self_value.zero_extend(max(0, other_value.size() - self_value.size()))
            other_value = other_value.zero_extend(max(0, self_value.size() - other_value.size()))

        return ValueProxy(getattr(self_value, op)(other_value))


    def __bool__(self):
        if not isinstance(self._value, claripy.ast.Base):
            return bool(self._value)

        assert isinstance(self._value, claripy.ast.Bool), "can't turn a ValueProxy over a non-bool AST into a bool"

        global __symbex__

        path_condition = [f if b else ~f for (f, b) in __symbex__.branches[:__symbex__.branch_index]]
        # note that 'state' here is a ValueProxy!
        outcomes = ValueProxy.unwrap(__symbex__.state).solver.eval_upto(self._value, 3, extra_constraints=path_condition) # ask for 3 just in case something goes wrong; we want 1 or 2

        if len(outcomes) == 1:
            return outcomes[0]

        assert len(outcomes) == 2, "solver eval_upto for a bool should return 1 or 2 outcomes"

        if __symbex__.branch_index == len(__symbex__.branches):
            __symbex__.branches.append((self._value, True))
        result = __symbex__.branches[__symbex__.branch_index][1]
        __symbex__.branch_index = __symbex__.branch_index + 1
        return result

    
    def __contains__(self, item):
        assert not isinstance(self._value, claripy.ast.Base), "contains cannot be called on an AST"
        return item in self._value

    def __len__(self):
        assert not isinstance(self._value, claripy.ast.Base), "len cannot be called on an AST"
        return len(self._value)

    def __int__(self):
        assert not isinstance(self._value, claripy.ast.Base), "int cannot be called on an AST"
        return int(self._value)


    def __invert__(self):
        return ValueProxy(~self._value)

    def __getitem__(self, item):
        return ValueProxy(self._value[item])

    def __and__(self, other):
        return self._op(other, "__and__")
    def __rand__(self, other):
        return self._op(other, "__rand__")
    
    def __or__(self, other):
        return self._op(other, "__or__")
    def __ror__(self, other):
        return self._op(other, "__ror__")

    def __eq__(self, other):
        return self._op(other, "__eq__")

    def __ne__(self, other):
        return self._op(other, "__ne__")

    def __lt__(self, other):
        return self._op(other, "__lt__") # TODO: signedness of {L/G}{E/T} and rshift

    def __le__(self, other):
        return self._op(other, "__le__")

    def __gt__(self, other):
        return self._op(other, "__gt__")

    def __ge__(self, other):
        return self._op(other, "__ge__")
    
    def __add__(self, other):
        return self._op(other, "__add__")
    def __radd__(self, other):
        return self._op(other, "__radd__")

    def __sub__(self, other):
        return self._op(other, "__sub__")
    def __rsub__(self, other):
        return self._op(other, "__rsub__")
    
    def __mul__(self, other):
        return self._op(other, "__mul__")
    def __rmul__(self, other):
        return self._op(other, "__rmul__")
    
    def __rshift__(self, other):
        return self._op(other, "LShR")
    
    def __lshift__(self, other):
        return self._op(other, "__lshift__")


def _symbex_one(state, prev_state, func, branches, choices):
    global __symbex__
    __symbex__.branches = branches
    __symbex__.branch_index = 0
    __symbex__.choices = choices
    __symbex__.choice_index = 0
    __symbex__.state = ValueProxy(state)
    __symbex__.prev_state = ValueProxy(prev_state)
    func()
    return __symbex__.branches[:__symbex__.branch_index], __symbex__.choices[:__symbex__.choice_index]

def _symbex(state, prev_state, func):
    branches = []
    while True:
        choices = []
        while True:
            try:
                (branches, choices) = _symbex_one(state, prev_state, func, branches, choices)
                break # yay, we found a good set of choices!
            except:
                # Prune choice sets that were fully explored
                while len(choices) > 0 and len(choices[-1]) == 1: choices.pop()
                # If all choices were explored, we failed
                if len(choices) == 0: raise
                # Otherwise, change the last choice
                choices[-1].pop(0)
        
        # Path succeeded
        yield ([f if b else ~f for (f, b) in branches], [cs[0] for cs in choices])

        # Prune branches that were fully explored
        while len(branches) > 0 and not branches[-1][1]: branches.pop()
        # If all branches were fully explored, we're done
        if len(branches) == 0: return
        # Otherwise, flip the last branch
        branches[-1] = False

def symbex(state, prev_state, program, func_name, args, globs):
    global __symbex__
    __symbex__ = _SymbexData()
    globs['__symbex__'] = __symbex__
    globs['__choose__'] = symbex_builtin_choose
    args = [ValueProxy(arg) for arg in args]
    # locals have to be the same as globals, otherwise Python encapsulates the program in a class and then one can't use classes inside it...
    exec(program, globs, globs)
    return _symbex(state, prev_state, lambda: globs[func_name](*args))
