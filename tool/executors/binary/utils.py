import angr

def read_str(state, ptr):
  result = ""
  while True:
    char = state.mem[ptr].uint8_t.resolved
    if char.symbolic:
      raise angr.AngrExitError("Trying to read a symbolic string!")
    char = state.solver.eval(char, cast_to=int)
    if char == 0:
      break
    result += chr(char)
    ptr = ptr + 1
  return result


def can_be_true(solver, cond, extra_constraints=[]):
  sols = solver.eval_upto(cond, 2, extra_constraints=extra_constraints)
  if len(sols) == 0:
    raise angr.AngrExitError("Could not evaluate: " + str(condition))
  else:
    return True in sols

def can_be_false(solver, cond, extra_constraints=[]):
  sols = solver.eval_upto(cond, 2, extra_constraints=extra_constraints)
  if len(sols) == 0:
    raise angr.AngrExitError("Could not evaluate: " + str(condition))
  else:
    return False in sols

def definitely_true(solver, cond, extra_constraints=[]):
  return not can_be_false(solver, cond, extra_constraints=extra_constraints)

def definitely_false(solver, cond, extra_constraints=[]):
  return not can_be_true(solver, cond, extra_constraints=extra_constraints)


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
