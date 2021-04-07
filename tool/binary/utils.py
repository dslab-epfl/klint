import angr
import claripy

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


def fork_guarded(proc, state, guard, case_true, case_false):
    guard_value = get_if_constant(state.solver, guard)
    if guard_value is not None:
        if guard_value:
            return case_true(state)
        else:
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
