import claripy
import claripy.frontend_mixins as cfms
from claripy.frontends import CompositeFrontend
from claripy import backends, SolverCompositeChild

import kalm


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
        template_solver = template_solver or SolverCompositeChild(track=track)
        template_solver_string = template_solver_string or SolverCompositeChild(track=track, backend=backends.z3)
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
