import angr
from angr.state_plugins.plugin import SimStatePlugin
from angr.state_plugins.sim_action import SimActionObject

from .sizes import TYPES, ALIASES

EXTRA = [
    "enum",
    "struct"
]

class CastsPlugin(angr.state_plugins.plugin.SimStatePlugin):
    @staticmethod
    def _fix(o):
        if isinstance(o, SimActionObject):
            o = o.ast
        return o

    def set_state(self, state):
        for t in TYPES:
            setattr(self, t, lambda arg, t=t: CastsPlugin._fix(arg)[getattr(self.state.sizes, t)-1:0])
        for (n, t) in ALIASES:
            setattr(self, n, lambda arg, t=t: CastsPlugin._fix(arg)[getattr(self.state.sizes, n)-1:0])
        for t in EXTRA:
            setattr(self, t, lambda arg: CastsPlugin._fix(arg))
        return super().set_state(state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return self

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True
