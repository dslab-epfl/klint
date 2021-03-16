# Standard/External libraries
import angr
import claripy

# Us
from .exceptions import SymbexException

def read_str(state, ptr):
  result = ""
  while True:
    char = state.memory.load(ptr, 1)
    if char.symbolic:
      raise SymbexException("Trying to read a symbolic string!")
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
    raise SymbexException("Could not evaluate: " + str(expr))
  if len(sols) == 1:
      return sols[0]
  return None

def get_exact_match(solver, item, candidates, assumptions=[], selector=lambda i: i):
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
        if definitely_true(solver, ~claripy.And(*assumptions) | (item == selector(cand))):
            return cand

    return None

def fork_always(proc, state, case_true, case_false):
    false_was_unsat = False
    if not state.satisfiable():
        raise SymbexException("too lazy to handle this :/")

    try:
        state_copy = state.copy()
        ret_expr = case_false(state_copy)
        state_copy.path.end_record(ret_expr) # hacky, see Path
        ret_addr = proc.cc.teardown_callsite(state_copy, ret_expr, arg_types=[False]*proc.num_args if proc.cc.args is None else None)
    except angr.errors.SimUnsatError:
        false_was_unsat = True
    else:
        proc.successors.add_successor(state_copy, ret_addr, claripy.true, 'Ijk_Ret')

    try:
        return case_true(state)
    except angr.errors.SimUnsatError as e:
        if false_was_unsat:
            raise SymbexException("Both cases were unsat!")
        else:
            raise e # let it bubble up to angr

def fork_guarded(proc, state, guard, case_true, case_false):
    if definitely_true(state.solver, guard):
        return case_true(state)
    elif definitely_false(state.solver, guard):
        return case_false(state)
    else:
        def case_true_prime(state):
            add_constraints_and_check_sat(state, guard)
            return case_true(state)
        def case_false_prime(state):
            add_constraints_and_check_sat(state, ~guard)
            return case_false(state)
        return fork_always(proc, state, case_true_prime, case_false_prime)

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
        return all(structural_eq(a[k], b[k]) for k in set(a.keys()).union(b.keys()))
    if isinstance(a, str) and isinstance(b, str):
        return a == b # no point in doing it the complicated way
    if hasattr(a, '__iter__') and hasattr(b, '__iter__') and hasattr(a, '__len__') and hasattr(b, '__len__'):
        return len(a) == len(b) and all(structural_eq(ai, bi) for (ai, bi) in zip(a, b))
    return a == b

def add_constraints_and_check_sat(state, *constraints, **kwargs):
    if False: # debug; slower!
        for c in constraints:
            state.add_constraints(c, **kwargs)
            if not state.satisfiable():
                raise angr.errors.SimUnsatError("UNSAT after adding constraint")
        return
    # TODO why is this simplify needed here? constraints shouldn't be added if c is like "false || true" but without it they are
    state.add_constraints(*[state.solver.simplify(c) for c in constraints], **kwargs)
    if not state.satisfiable():
        raise angr.errors.SimUnsatError("UNSAT after adding constraints")