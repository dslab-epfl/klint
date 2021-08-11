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

    def simplify(self, **kwargs):
        # TODO: Investigate this. There seems to be a bug in the simplification that drops constraints
        return self.constraints
        """prev_cons = self.constraints.copy()
        result = super().simplify(**kwargs)
        if any("map_values_4_present" in str(c) and (c.op == 'BoolS' or c.op == 'Not') for c in prev_cons) and \
           not any("map_values_4_present" in str(c) and (c.op == 'BoolS' or c.op == 'Not') for c in self.constraints):
            print("what") # at this point the map present bit has 2 possible values!
        return result"""
