from typing import Generic, TypeVar

import claripy

from .symbex_data import get_symbex, set_symbex

T = TypeVar('T')

class ValueProxy(Generic[T]):
    @staticmethod
    def wrap(value: T) -> 'ValueProxy[T]':
        if value is None:
            return None
        if callable(value):
            return lambda *args, **kwargs: ValueProxy.wrap(value(*[ValueProxy.unwrap(arg) for arg in args], **{k: ValueProxy.unwrap(v) for (k, v) in kwargs.items()}))
        return ValueProxy(value)

    @staticmethod
    def unwrap(value: 'ValueProxy[T]') -> T:
        if callable(value):
            return lambda *args, **kwargs: ValueProxy.unwrap(value(*[ValueProxy.wrap(arg) for arg in args], **{k: ValueProxy.wrap(v) for (k, v) in kwargs.items()}))
        if isinstance(value, list):
            return [ValueProxy.unwrap(i) for i in value]
        if not isinstance(value, ValueProxy):
            return value
        return value._value

    def __init__(self, value):
        assert value is not None and value is not NotImplemented and not isinstance(value, ValueProxy), "value should make sense"
        self._value = value

    def __getattr__(self, name):
        if name[0] == "_":
            # Private members, for use within the class itself
            return super().__getattr__(name, value)

        if hasattr(self._value, name):
            result = getattr(self._value, name)
            if result is None:
                return None
            return ValueProxy.wrap(result)

        raise Exception(f"idk what to do about attr '{name}'")

    def __setattr__(self, name, value):
        assert name[0] == "_", "can only set private variables, which should be from within the class itself"
        return super().__setattr__(name, value)

    def _op(self, other, op):
        other_value = other
        self_value = self._value

        # Convert if needed
        if isinstance(other, ValueProxy):
            other_value = other._value
        if isinstance(other_value, float) and other_value == other_value // 1:
            other_value = int(other_value)
        if isinstance(other_value, int) and not isinstance(other_value, bool): # Python quirk: bool subclasses int...
            if not isinstance(self_value, int):
                assert isinstance(self_value, claripy.ast.BV), "what else could it be?"
                other_value = claripy.BVV(other_value, max(8, self_value.size())) # 8 bits minimum

        # If we're bigger, extend the other; otherwise, extend the result
        # This is so that e.g. '16-bit A' + '64-bit B' is computed as 16-bits, as it would be in source
        result_size = None
        if isinstance(self_value, claripy.ast.BV):
            if self_value.size() > other_value.size():
                other_value = other_value.zero_extend(self_value.size() - other_value.size())
            elif self_value.size() < other_value.size():
                result_size = other_value.size()
                other_value = other_value[self_value.size()-1:0]

        result = getattr(self_value, op)(other_value)
        if result_size is not None and isinstance(result, claripy.ast.BV): # don't try to extend bools!
            result = result.zero_extend(result_size - result.size())

        return ValueProxy.wrap(result)


    def __bool__(self):
        if not isinstance(self._value, claripy.ast.Base):
            return bool(self._value)

        assert isinstance(self._value, claripy.ast.Bool), "can't turn a ValueProxy over a non-bool AST into a bool"

        # note that 'symbex.state' here is a ValueProxy!
        symbex = get_symbex()

        path_condition = [f if b else ~f for (f, b) in symbex.branches[:symbex.branch_index]]
        outcomes = ValueProxy.unwrap(symbex.state).solver.eval_upto(self._value, 3, extra_constraints=path_condition) # ask for 3 just in case something goes wrong; we want 1 or 2

        if len(outcomes) == 1:
            return outcomes[0]

        assert len(outcomes) == 2, "solver eval_upto for a bool should return 1 or 2 outcomes"
        print("Multivalued! For: ", self._value)

        if symbex.branch_index == len(symbex.branches):
            symbex.branches.append((self._value, True))
        result = symbex.branches[symbex.branch_index][1]
        symbex.branch_index = symbex.branch_index + 1

        ValueProxy.unwrap(symbex.state).solver.add(self._value if result else ~self._value)

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

    def __iter__(self):
        assert not isinstance(self._value, claripy.ast.Base), "iter cannot be called on an AST"
        return map(ValueProxy.wrap, iter(self._value))

    def __invert__(self):
        return ValueProxy.wrap(~self._value)

    def __getitem__(self, item):
        return ValueProxy.wrap(self._value[ValueProxy.unwrap(item)])

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

    def __floordiv__(self, other):
        return self._op(other, "__floordiv__")
    def __rfloordiv__(self, other):
        return self._op(other, "__rfloordiv__")

    def __rshift__(self, other):
        return self._op(other, "LShR")

    def __lshift__(self, other):
        return self._op(other, "__lshift__")
