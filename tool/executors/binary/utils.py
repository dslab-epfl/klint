import angr
import claripy


class FakeState:
    def __init__(self):
        self._global_condition = None

fake_state_instance = FakeState()
def solver_copy(solver):
    result = solver.copy()
    result.state = fake_state_instance # otherwise it complains
    return result


def read_str(state, ptr):
  result = ""
  while True:
    char = state.mem[ptr].uint8_t.resolved
    if char.symbolic:
      raise angr.AngrExitError("Trying to read a symbolic string!")
    char = state.solver.eval_one(char, cast_to=int)
    if char == 0:
      break
    result += chr(char)
    ptr = ptr + 1
  return result


def can_be_true(solver, cond):
  sols = solver_copy(solver).eval_upto(cond, 2)
  if len(sols) == 0:
    raise angr.AngrExitError("Could not evaluate: " + str(cond))
  return True in sols

def can_be_false(solver, cond):
  sols = solver_copy(solver).eval_upto(cond, 2)
  if len(sols) == 0:
    raise angr.AngrExitError("Could not evaluate: " + str(cond))
  return False in sols

def can_be_true_or_false(solver, cond):
  sols = solver_copy(solver).eval_upto(cond, 2)
  if len(sols) == 0:
    raise angr.AngrExitError("Could not evaluate: " + str(cond))
  return len(sols) == 2

def definitely_true(solver, cond):
  return not can_be_false(solver, cond)

def definitely_false(solver, cond):
  return not can_be_true(solver, cond)

def get_if_constant(solver, expr):
  sols = solver_copy(solver).eval_upto(expr, 2, cast_to=int)
  if len(sols) == 0:
    raise angr.AngrExitError("Could not evaluate: " + str(expr))
  if len(sols) == 1:
      return sols[0]
  return None


def fork_always(proc, case_true, case_false):
  false_was_unsat = False
  original_sat = proc.state.satisfiable()
  try:
    state_copy = proc.state.copy()
    ret_expr = case_false(state_copy)
    ret_addr = proc.cc.teardown_callsite(state_copy, ret_expr, arg_types=[False]*proc.num_args if proc.cc.args is None else None)
  except angr.errors.SimUnsatError:
    false_was_unsat = True
    pass
  else:
    proc.successors.add_successor(state_copy, ret_addr, proc.state.solver.true, 'Ijk_Ret')

  try:
    return case_true(proc.state)
  except angr.errors.SimUnsatError as e:
    if false_was_unsat:
      raise angr.AngrExitError("Both cases were unsat!")
    else:
      raise e # let it bubble up to angr

def fork_guarded(proc, guard, case_true, case_false):
  if definitely_true(proc.state.solver, guard):
    return case_true(proc.state)
  elif definitely_false(proc.state.solver, guard):
    return case_false(proc.state)
  else:
    def case_true_prime(state):
      state.add_constraints(guard)
      return case_true(state)
    def case_false_prime(state):
      state.add_constraints(state.solver.Not(guard))
      return case_false(state)
    return fork_always(proc, case_true_prime, case_false_prime)

def fork_guarded_has(proc, ghost_map, key, case_has, case_not):
  (value, present) = proc.state.maps.get(ghost_map, key)
  def case_true(state):
      return case_has(state, value)
  def case_false(state):
      return case_not(state)
  return fork_guarded(proc, present, case_true, case_false)


def structural_eq(a, b):
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    if isinstance(a, claripy.ast.base.Base) and isinstance(b, claripy.ast.base.Base):
        return a.structurally_match(b)
    if hasattr(a, '_asdict') and hasattr(b, '_asdict'): # namedtuple
        ad = a._asdict()
        bd = b._asdict()
        return all(structural_eq(ad[k], bd[k]) for k in set(ad.keys()).union(bd.keys()))
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(structural_eq(ai, bi) for (ai, bi) in zip(a, b))
    if isinstance(a, tuple) and isinstance(b, tuple):
        return structural_eq(list(a), list(b))
    return a == b