# Lightweight symbex, see https://hoheinzollern.files.wordpress.com/2008/04/seer1.pdf
# This implementation assumes a 'solver' object with a method 'eval_upto(formula, max_vals_count, extra_constraints=[]) -> [vals]'

__path__ = []
__pathcondition__ = []

class SolverFailedException(Exception): pass
class SolverMismatchException(Exception): pass

class BoolProxy:
  def __init__(self, solver, formula):
    self.solver = solver
    self.formula = formula
  def __bool__(self):
    global __path__, __pathcondition__

    outcomes = self.solver.eval_upto(self.formula, 3, extra_constraints=__pathcondition__) # ask for 3 just in case something goes wrong; we want 1 or 2

    if len(outcomes) == 0: raise SolverFailedException()
    if len(outcomes) == 1: return outcomes[0]
    if len(outcomes)  > 2: raise SolverFailedException()

    branch = True
    if len(__path__) > len (__pathcondition__):
      branch = __path__[len(__pathcondition__)]
    else:
      __path__.append(branch)

    __pathcondition__.append(self.formula if branch else ~self.formula)
    return branch

class ValueProxy:
  def __init__(self, solver, wrapped):
    self.solver = solver
    self.wrapped = wrapped
  def __eq__(self, other): # self == other
    other_val = other
    if isinstance(other, ValueProxy):
      if self.solver != other.solver: raise SolverMismatchException()
      other_val = other.wrapped
    return BoolProxy(self.solver, self.wrapped == other_val)
  def __req__(self, other): # other == self
    return self.__eq__(other)
  def __getitem__(self, key): # self[key]
    return ValueProxy(self.solver, self.wrapped.__getitem__(key))
  def __getattr__(self, name): # self.name
    return ValueProxy(self.solver, getattr(self.wrapped, name))
  def __repr__(self): # str(self)
    return self.wrapped.__repr__()


def proxy(solver, obj):
  return ValueProxy(solver, obj)


def symbex(run_func, report_func):
  global __path__, __pathcondition__
  while True:
    __pathcondition__ = []
    run_func()
    report_func(__pathcondition__)
    while len(__path__) > 0 and not __path__[-1]: __path__.pop()
    if __path__ == []: break
    __path__[-1] = False
