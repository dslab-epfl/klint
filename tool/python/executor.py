#!/usr/bin/env python

# Us
from . import symbex

def execute(solver, spec_text, spec_args, spec_externals):
  state_box = [{}] # box it so we can pass the state around
  globals = {}
  for i, a in enumerate(spec_args):
    globals['__arg' + str(i)] = symbex.proxy(solver, a)
  for name, method in spec_externals.items():
    # avoid capturing the loop variable in the lambda...
    def build_lambda(method): return lambda *args, **kwargs: method(state_box[0], *args, **kwargs)
    globals[name] = build_lambda(method)

  def run():
    state_box.clear()
    state_box.append({})
    exec(
      spec_text + '\n' + 'spec(' + ','.join(['__arg' + str(i) for (i, a) in enumerate(spec_args)]) + ')' + '\n',
      # globals
      globals,
      # locals
      {}
    )

  results = []
  def report(pathcond):
    results.append((pathcond, state_box[0]))

  symbex.symbex(run, report)
  return results
