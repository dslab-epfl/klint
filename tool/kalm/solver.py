import claripy
import claripy.frontend_mixins as cfms
from claripy.frontends import CompositeFrontend
from claripy import backends, SolverCompositeChild

import kalm

# Optimization 1: for some reason using the SMT tactic instead of the default is faster
import z3; z3.set_param('tactic.default_tactic', 'smt')
# Optimization 2: Using QF_ABV explicitly is faster, even though all our queries are QF_BV (see https://github.com/Z3Prover/z3/issues/5655)
class KalmZ3Backend(claripy._backends_module.BackendZ3):
    def solver(self, timeout=None):
        return z3.SolverFor("QF_ABV", ctx=self._context)

# Keep only what we need in the solver
# We especially don't want ConstraintExpansionMixin, which adds constraints after an eval
# e.g. eval_upto(x, 2) -> [1, 2] results in added constraints x != 1 and x != 2
class KalmSolver(
    cfms.ConstraintFixerMixin, # fixes types (e.g. bool to BoolV)
    cfms.ConcreteHandlerMixin, # short-circuit on concrete vals
    cfms.EagerResolutionMixin, # for eager backends
    cfms.ConstraintFilterMixin, # applies constraint filters (do we ever use that?)
    cfms.ConstraintDeduplicatorMixin, # avoids duplicate constraints
    cfms.SatCacheMixin, # caches satisfiable()
    cfms.SimplifySkipperMixin, # caches the "simplified" state
    cfms.SimplifyHelperMixin, # simplifies before calling the solver
    cfms.CompositedCacheMixin, # sounds useful
    CompositeFrontend # the actual frontend
):
    def __init__(self, template_solver=None, track=False, template_solver_string=None, **kwargs):
        template_solver = template_solver or SolverCompositeChild(track=track, backend=KalmZ3Backend())
        # we do not override template_solver_string if it's None given our optimization to force QF_ABV, it wouldn't work with strings; but we don't use them anyway
        super().__init__(template_solver, template_solver_string, track=track, **kwargs)

    def add(self, constraints, **kwargs):
        if kalm.DEBUG:
            for con in constraints:
                super().add([con], **kwargs)
                if not self.satisfiable():
                    raise Exception("UNSAT after adding constraint: " + str(con))
        return super().add(constraints, **kwargs)

    # Specialized function to merge solvers that are expected to have a lot in common
    # Anything in common is kept as-is, the rest is added as (merge_cond implies noncommon_constraint)
    # This doesn't help perf, but massively helps readability
    def merge(self, others, merge_conditions, common_ancestor=None):
        merged = self.blank_copy()
        divergence_index = 0
        min_length = min(len(self.constraints), *[len(s.constraints) for s in others])
        while divergence_index < min_length:
            for solver in others:
                if self.constraints[divergence_index] is not solver.constraints[divergence_index]:
                    break
            else:
                merged.add(self.constraints[divergence_index])
                divergence_index = divergence_index + 1
                continue
            break
        for solver, cond in zip([self] + others, merge_conditions):
            for extra in solver.constraints[divergence_index:]:
                merged.add(~cond | extra)
        merged.add(claripy.Or(*merge_conditions))
        return True, merged

    def simplify(self, **kwargs):
        # not sure why but if we allow simplifying, verification is like 50% slower :-/
        return self.constraints
