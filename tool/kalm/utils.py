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

    # TODO move this function to ghostmaps, that's the only way this makes sense
    if not item.symbolic:
        return None

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

# returns ([only_left], [both], [only_right])
def structural_diff(left, right):
    only_left = []
    both = []
    only_right = right.copy()
    for item in left:
        for candidate in right:
            if structural_eq(item, candidate):
                only_right.remove(item)
                both.append(item)
                break
        else:
            only_left.append(item)
    return (only_left, both, only_right)

# Requires a 'meta_type' such that there is metadata on the type from pointers to a class with 'count' and 'size'
# Guarantees that:
# - Result is of the form (base, index, offset)
# - 'base': BV, is a symbolic pointer
# - 'index': BV, is a symbolic index
# - 'offset': int, is an offset in bits, concrete
def base_index_offset(state, addr, meta_type, allow_failure=False):
#    if isinstance(addr, int):
#        if allow_failure:
#            return (None, None, None)
#        raise Exception("B_I_O was given an int")

    def force_burrow_ite(value):
        # claripy's ite_burrowed except it's recursive
        # so that if(x, a + 1, if(y, a + 2, if(z, a + 3, a + 4))) turns into a + if(x, 1, if(y, 2, if(z, 3, 4)))
        if value.op != 'If':
            return value
        return claripy.If(value.args[0], force_burrow_ite(value.args[1]), force_burrow_ite(value.args[2])).ite_burrowed

    def simplify(value):
        # uggggh angr why do you do this to me? :( the case that inspired this is one that looks like ite_excavated/burrowed should easily work but it did not...
        if value.op == '__add__':
            return sum(simplify(a) for a in value.args)
        # Sometimes we get an If or a Concat that fits our assumptions fine but only if we first excavate then burrow the ifs
        # e.g. concat(If(X, a1, b1), If(X, a2, b2), ...) -> If(X, concat(a1, a2, ...), concat(b1, b2, ...))
        value = value.ite_excavated
        # Avoid ifs whose condition is constant
        while value.op == 'If':
            cond_const = get_if_constant(state.solver, value.args[0])
            if cond_const is True:
                value = value.args[1]
            elif cond_const is False:
                value = value.args[2]
            else:
                break # no more simplification possible
            value = value.ite_excavated
        return state.solver.simplify(force_burrow_ite(value))

    addr = simplify(addr)

    if addr.op == '__add__':
        (base, meta) = state.metadata.find(meta_type, addr.args)
        if base is None:
            # Annoying tricky part that goes against the design of this function:
            # when we symbex JITed BPF code, the "arrays" are at fixed offsets
            # So if there are any non-symbolic keys in the metadata, try them all manually...
            for (k, v) in state.metadata.get_all(meta_type).items():
                if not k.symbolic:
                    for arg in addr.args:
                        if not arg.symbolic:
                            if definitely_true(state.solver, (arg - k).ULT(v.size)):
                                base = k
                                meta = v
                                addr = addr - arg + base # trick so the 'added' later works, let's not dirty the "clean" path
                                break
                    if base is not None:
                        break
        if base is None:
            if allow_failure:
                return (None, None, None)
            raise Exception("!= 1 candidate for base??? are you symbolically indexing a global variable or something?")

        # 2nd parameter is 'start', but cannot be a named parameter before Python 3.8...
        added = sum((a for a in addr.args if not a.structurally_match(base)), claripy.BVV(0, addr.size()))
        offset = state.solver.eval_one(_modulo_simplify(state.solver, added, meta.size), cast_to=int)
        index = _div_simplify(state.solver, (added - offset), meta.size)
        return (base, index, offset * 8)

    # Maybe it's e.g. a BVS and we know about it
    meta = state.metadata.get_or_none(meta_type, addr)
    if meta is not None:
        return (addr, claripy.BVV(0, addr.size()), 0)

    if allow_failure:
        return (None, None, None)
    raise Exception("B_I_O doesn't know what to do with: " + str(addr) + " of type " + str(type(addr)) + " ; op is " + str(addr.op) + " ; args is " + str(addr.args) + " ; constrs are " + str(state.solver.constraints))


# Optimization: simplify modulos and divs, this can save minutes, especially for non-power-of-2 modulos such as 6-byte MAC addresses
# Ideally this is something Claripy or Z3 would do...

# Returns a dictionary such that ast == sum(e.ast * m for (e, m) in result.items())
def _as_mult_add(ast):
    if ast.op == 'Concat' and len(ast.args) == 2 and \
       ast.args[1].op == 'BVV' and ast.args[1].args[0] == 0:
        nested = _as_mult_add(ast.args[0])
        return {e.ast.zero_extend(ast.args[1].size()).cache_key: m << ast.args[1].size() for (e, m) in nested.items()}
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

# group things together, e.g. if we end up with '(0 .. x[62:0])' and 'x', group them iff x[63] == 0
def _as_mult_add_outer(ast, solver):
    result = {}
    for (e, m) in _as_mult_add(ast).items():
        if e.ast.op == 'ZeroExt' and e.ast.args[1].op == 'Extract' and e.ast.args[1].args[1] == 0:
            if definitely_true(solver, e.ast.args[1].args[2] == e.ast):
                e = e.ast.args[1].args[2].cache_key
        if e in result:
            result[e] += m
        else:
            result[e] = m
    return result

# Returns a simplified form of a % b
def _modulo_simplify(solver, a, b):
    result = 0
    for (e, m) in _as_mult_add_outer(a, solver).items():
        # note that is_true just performs basic checks, so if _as_mult_add decomposed it nicely, we'll skip the modulo entirely
        # e.g. (x * 4) % 2 can be simplified to 0
        if not (e.ast % b == claripy.BVV(0, a.size())).is_true() and not (m % b == claripy.BVV(0, a.size())).is_true():
            result += e.ast * m
    return result % b

# Returns a simplified form of a // b
def _div_simplify(solver, a, b):
    if (a == 0).is_true():
        return a
    if (b == 1).is_true():
        return a

    def make_term(e, m, b):
        if (m % b == 0).is_true():
            return e
        return e * m // b
    decomposed = _as_mult_add_outer(a, solver)
    return sum(make_term(e.ast, m, b) for (e, m) in decomposed.items())
