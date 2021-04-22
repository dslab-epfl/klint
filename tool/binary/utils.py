import angr
import claripy
import math

def read_str(state, ptr):
    result = ""
    while True:
        char = state.memory.load(ptr, 1)
        if char.symbolic:
            raise Exception("Trying to read a symbolic string!")
        char = state.solver.eval_one(char, cast_to=int)
        if char == 0:
            break
        result += chr(char)
        ptr = ptr + 1
    return result


def can_be_true(solver, cond):
    return solver.satisfiable(extra_constraints=[cond])

def can_be_false(solver, cond):
    return solver.satisfiable(extra_constraints=[~cond])

def definitely_true(solver, cond):
    return not can_be_false(solver, cond)

def definitely_false(solver, cond):
    return not can_be_true(solver, cond)

def get_if_constant(solver, expr, **kwargs):
    sols = solver.eval_upto(expr, 2, **kwargs)
    if len(sols) == 0:
        raise Exception("Could not evaluate: " + str(expr))
    if len(sols) == 1:
        return sols[0]
    return None

def get_exact_match(solver, item, candidates, assumption=claripy.true, selector=lambda i: i):
    # at one point this exact pattern, even after calling solver.simplify, caused the solver to hang...
    # but simplifying this way (which is correct; (0#4 .. x) * 0x10 / 0x10 == (0#4 .. x)) made it go through
    # the structurally_match path, which is all good
    # TODO check if this is still needed?
    if item.op == "__floordiv__" and \
       str(item.args[1]) == "<BV64 0x10>" and \
       item.args[0].op == "__add__" and \
       len(item.args[0].args) == 1 and \
       item.args[0].args[0].op == "__mul__" and \
       item.args[0].args[0].args[1] is item.args[1] and \
       item.args[0].args[0].args[0].op == "ZeroExt" and \
       item.args[0].args[0].args[0].args[0] == 4:
        item = item.args[0].args[0].args[0]

    for cand in candidates:
        if item.structurally_match(selector(cand)):
            return cand

    for cand in candidates:
        if definitely_true(solver, ~assumption | (item == selector(cand))):
            return cand

    return None

# TODO move to a subclass of SimProcedure?
def fork_guarded(proc, state, guard, case_true, case_false):
    guard_value = get_if_constant(state.solver, guard)
    if guard_value is not None:
        if guard_value:
            return case_true(state)
        return case_false(state)

    state_copy = state.copy()
    state_copy.solver.add(~guard)
    false_ret_expr = case_false(state_copy)
    state_copy.path.end_record(false_ret_expr) # hacky, see Path
    false_ret_addr = proc.cc.teardown_callsite(state_copy, false_ret_expr, arg_types=[False]*proc.num_args if proc.cc.args is None else None)
    proc.successors.add_successor(state_copy, false_ret_addr, claripy.true, 'Ijk_Ret')

    state.solver.add(guard)
    return case_true(state)
def fork_guarded_has(proc, state, ghost_map, key, case_has, case_not):
    (value, present) = state.maps.get(ghost_map, key)
    def case_true(state):
        return case_has(state, value)
    def case_false(state):
        return case_not(state)
    return fork_guarded(proc, state, present, case_true, case_false)


def structural_eq(a, b):
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    if isinstance(a, claripy.ast.Base) and isinstance(b, claripy.ast.Base):
        return a.structurally_match(b)
    if hasattr(a, '_asdict') and hasattr(b, '_asdict'): # namedtuple
        ad = a._asdict()
        bd = b._asdict()
        return structural_eq(ad, bd)
    if isinstance(a, dict) and isinstance(b, dict):
        return all(k in a and k in b and structural_eq(a[k], b[k]) for k in set(a.keys()).union(b.keys()))
    if isinstance(a, str) and isinstance(b, str):
        return a == b # no point in doing it the complicated way
    if hasattr(a, '__iter__') and hasattr(b, '__iter__') and hasattr(a, '__len__') and hasattr(b, '__len__'):
        return len(a) == len(b) and all(structural_eq(ai, bi) for (ai, bi) in zip(a, b))
    return a == b


# Requires a 'meta_type' such that there is metadata on the type from pointers to a class with 'count' and 'size'
# Guarantees that:
# - Result is of the form (base, index, offset)
# - 'base': BV, is a symbolic pointer
# - 'index': BV, is a symbolic index
# - 'offset': int, is an offset in bits, concrete
def base_index_offset(state, addr, meta_type, allow_failure=False):
    if isinstance(addr, int):
        if allow_failure:
            return (None, None, None)
        raise Exception("B_I_O was given an int")

    def as_simple(val):
        if val.op == "BVS": return val
        if val.op == '__add__' and len(val.args) == 1: return as_simple(val.args[0])
        return None

    simple_addr = as_simple(addr)
    if simple_addr is not None:
        return (simple_addr, claripy.BVV(0, 64), 0) # Directly addressing a base, i.e., base[0]

    if addr.op == '__add__':
        base = [a for a in map(as_simple, addr.args) if a is not None]

        if len(base) == 0:
            # let's hope this can be solved by simplifying?
            addr = state.solver.simplify(addr)
            base = [a for a in map(as_simple, addr.args) if a is not None]

        if len(base) == 1:
            base = base[0]
        else:
            base = [b for b in base if any(b.structurally_match(k) for k in state.metadata.get_all(meta_type).keys())]
            if len(base) == 1:
                base = base[0]
            else:
                # TODO this check should come earlier and the result should be reused... it's more like "filter out stuff that's definitely not a pointer"
                base = [b for b in addr.args if state.metadata.get_or_none(meta_type, b) is not None]
                if len(base) != 1:
                    if allow_failure:
                        return (None, None, None)
                    raise Exception("!= 1 candidate for base??? are you symbolically indexing a global variable or something?")
                base = base[0]
        added = sum([a for a in addr.args if not a.structurally_match(base)])

        meta = state.metadata.get_or_none(meta_type, base)
        if meta is None:
            if allow_failure:
                return (None, None, None)
            raise Exception("B_I_O has no info about: " + str(base))

        offset = state.solver.eval_one(_modulo_simplify(added, meta.size), cast_to=int)
        # Don't make the index be a weird '0 // ...' expr if we can avoid it, but don't call the solver for that
        if (added == offset).is_true():
            index = claripy.BVV(0, 64)
        else:
            index = (added - offset) // meta.size
        return (base, index, offset * 8)

    addr = state.solver.simplify(addr) # this handles the descriptor addresses, which are split between two NIC registers
    if addr.op == "BVS":
        return (addr, claripy.BVV(0, 64), 0)

    if allow_failure:
        return (None, None, None)
    raise Exception("B_I_O doesn't know what to do with: " + str(addr) + " of type " + str(type(addr)) + " ; op is " + str(addr.op) + " ; args is " + str(addr.args) + " ; constrs are " + str(state.solver.constraints))


# Optimization: the "_modulo_simplify" function allows base_index_offset to avoid calling the solver when computing the offset of a memory access

# Returns a dictionary such that ast == sum(e.ast * m for (e, m) in result.items())
def _as_mult_add(ast):
    if ast.op == '__lshift__':
        nested = _as_mult_add(ast.args[0])
        return {e: m << ast.args[1] for (e, m) in nested.items()}
    if ast.op == '__add__' or ast.op == '__sub__':
        coeff = 1
        result = {}
        for arg in ast.args:
            nested = _as_mult_add(arg)
            for e, m in nested.items():
                result.setdefault(e, 0)
                result[e] += coeff * m
            coeff = 1 if ast.op == '__add__' else -1
        return result
    if ast.op == '__mul__':
        lone_sym = None
        con = None
        for arg in ast.args:
            if arg.symbolic:
                if lone_sym is not None:
                    break
                lone_sym = arg
            else:
                # Avoid introducing "1 * ..." terms
                if con is None:
                    con = arg
                else:
                    con *= arg
        else:
            if con is None:
                return _as_mult_add(lone_sym)
            else:
                return {e: m * con for (e, m) in _as_mult_add(lone_sym).items()}
    return {ast.cache_key: 1}

# Returns a simplified form of a % b
# TODO check how much time this really saves
def _modulo_simplify(a, b):
    result = 0
    for (e, m) in _as_mult_add(a).items():
        # note that is_true just performs basic checks, so if _as_mult_add decomposed it nicely, we'll skip the modulo entirely
        # e.g. (x * 4) % 2 can be simplified to 0
        if not (e.ast % b == claripy.BVV(0, a.size())).is_true() and not (m % b == claripy.BVV(0, a.size())).is_true():
            result += e.ast * m
    return result % b