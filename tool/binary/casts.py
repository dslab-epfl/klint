import angr
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
        for type in TYPES:
            setattr(self, type, lambda s, arg: CastsPlugin._fix(arg)[getattr(s.state.sizes, type)-1:0])
        for (name, type) in ALIASES.items():
            setattr(self, name, lambda s, arg: CastsPlugin._fix(arg)[getattr(s.state.sizes, type)-1:0])
        for type in EXTRA:
            setattr(self, type, lambda s, arg: CastsPlugin._fix(arg))
        return super().set_state(state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return self

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True
